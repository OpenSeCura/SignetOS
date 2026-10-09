# Agent Sandboxing: Existing Systems vs. SignetOS

Agents run generated code, call shell commands, and read untrusted inputs from the web or emails. Because prompt-level rules are easy to bypass via prompt injection, sandboxing has to happen in the OS or runtime outside the agent.

Here is what current systems (NVIDIA OpenShell, Firecracker/E2B, CaMeL, Fides) do to isolate agents, and how we could do it in SignetOS.

## 1. Process and Kernel Isolation

**What they do:**
* **MicroVMs (Firecracker, E2B):** Run each agent in its own lightweight VM with a separate Linux kernel so a kernel bug doesn't compromise the host. The downside is higher memory overhead and slower boot/snapshot times.
* **Containers + syscall filters (OpenShell, gVisor, Bubblewrap):** Run the agent as an unprivileged Linux user, drop Linux capabilities, and use `seccomp` to block dangerous syscalls.

**How we could do it in SignetOS:**
* Put each agent, subagent, and tool in its own compartment sharing a single address space.
* Hardware capabilities enforce memory bounds and permissions directly, avoiding the need for separate VMs or page-table switches.
* System calls aren't globally available; an agent would only be able to call the syscalls present in its capability table.

## 2. Filesystem and Storage Access

**What they do:**
* **Path allowlists (OpenShell):** Use Linux Landlock at startup to restrict the agent to reading or writing a list of directory paths from a YAML config.
* **Disposable overlays:** Give the container a temporary filesystem and wipe it when the run ends.

**How we could do it in SignetOS:**
* **No ambient path access:** Instead of starting with a global filesystem and blocking paths, an agent would only be able to touch files or directories it holds a capability for.
* **Fine-grained file capabilities:** Capabilities could grant access to a directory, a single file, or a specific set of operations (such as read-only or append-only for logs). An agent could narrow a file capability before passing it to a tool or subagent.
* **Storage quotas as capabilities:** Allocating disk space or creating files would be charged against a storage quota capability (bounding space, object counts, or I/O bandwidth). A parent agent could carve out a smaller storage quota for a subagent and reclaim it when the task finishes.

## 3. Network and Tool Mediation

**What they do:**
* **External proxy + syscall trapping (OpenShell):** Disable direct networking inside the sandbox. Use `seccomp` to trap every network or DNS syscall, check `/proc` to see which binary made the call, and forward the traffic over a socket to an external Supervisor process. The Supervisor checks a YAML policy (allowed hosts, HTTP methods, REST paths, MCP tools) before opening the real connection.

**How we could do it in SignetOS:**
* Run the Supervisor or Network Manager as a separate compartment.
* Instead of trapping socket syscalls and serializing traffic over a proxy socket, the agent would call the network/tool compartment directly. The thread switches compartments in a few instructions while the kernel clears unused registers and hides the caller's stack.
* Instead of filtering raw IP addresses or URLs in a proxy, we could give the agent sealed handles for the specific endpoints or MCP tools it is allowed to call.

## 4. Secrets and API Keys

**What they do:**
* **Proxy header injection (OpenShell):** Keep API keys out of the sandbox's environment variables and disk. When the agent makes an approved HTTP request through the Supervisor proxy, the Supervisor injects the API key into the request headers on the way out.

**How we could do it in SignetOS:**
* Keep secrets inside a Credential Manager compartment.
* Give the agent a sealed handle that represents permission to use a key, never the key string itself.
* The agent would pass that handle when calling an external service, and could pass a restricted version of it to a subagent, without needing an HTTP proxy to rewrite headers in transit.

## 5. Prompt Injection and Data Exfiltration

**What they do:**
* **Separate planner and worker models (CaMeL, IsolateGPT):** Split the agent into a privileged planner (which plans tool calls from the user's prompt and never sees raw untrusted text) and unprivileged workers (which read untrusted web pages or emails, but have no direct access to tools).
* **Information flow / taint tracking (Fides):** Track when an agent reads confidential data alongside untrusted data, and block tainted outputs from being sent to external network sinks or sensitive tools.

**How we could do it in SignetOS:**
* **Keep untrusted text out of the planner using sealed data handles:** When a tool fetches untrusted data (like an email or web page), it can return a *sealed capability handle* to that data rather than raw text. If the planner compartment doesn't hold the unseal key, it can pass the handle to a summarizer or parser compartment, but cannot read the bytes itself. Because the untrusted text never enters the planner's context, it cannot prompt-inject the planner into changing the execution plan.
* **Lock down destinations before reading untrusted data:** In normal systems, a prompt injection exfiltrates data by tricking the model into passing a new URL, DNS name, or email address as a string argument to a tool. In SignetOS, raw strings don't grant access. The planner can mint narrow, sealed capabilities for the exact destinations requested by the user (e.g., a handle that *only* sends to `alice@company.com`) before any untrusted data is read. Even if a downstream worker is compromised by untrusted text, it cannot redirect output to `attacker.com` because it holds no capability for that destination.
* **Track taint and confidentiality in sealed object headers:** Because compartments cannot forge or alter the header of a sealed object, the system can tag data handles with provenance (`confidential`, `untrusted`). If a compartment touches both confidential and untrusted inputs, its output handle inherits both tags, and external network or tool compartments can automatically refuse to send it out.

## 6. Spawning Subagents and Resource Limits

**What they do:**
* **Central control plane + cgroups (OpenShell):** To run a subagent with fewer permissions, the parent writes a new YAML policy, checks it, and asks the central Gateway to spin up a new container with Linux cgroup limits on RAM and CPU.

**How we could do it in SignetOS:**
* An agent could directly split its own memory, CPU time, and disk quotas, and narrow its own service handles, to spawn a subagent compartment itself.
* Because capabilities and quotas can only be reduced when passed down, a subagent could never use more resources or permissions than its parent.
* When the subagent is done, tearing down its compartment and quotas would return all resources to the parent immediately.

## 7. Policy Checking and Auditing

**What they do:**
* **Static YAML verification (OpenShell Prover):** Run an SMT solver (`openshell-prover`) on the YAML policy before launch (or when an agent asks for new network rules) to prove it doesn't allow more access than a baseline `boundary.yaml` file.

**How we could do it in SignetOS:**
* Each program image has a manifest listing the memory, quotas, and services it wants. We could run the same kind of solver check on that manifest before launching the compartment.
* In Linux, a process's real permissions are spread across UIDs, open file descriptors, env vars, and namespaces. In SignetOS, everything a compartment can do is in its capability table, so we could also inspect or revoke an agent's exact permissions while it is running.
