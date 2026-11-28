"""Read-only runtime checks for the A network layout. No test packets or secrets."""
import json
import subprocess
import sys

def docker(*args):
    result = subprocess.run(["docker", *args], capture_output=True, encoding="utf-8", timeout=15)
    if result.returncode:
        raise RuntimeError("Docker command failed: " + " ".join(args[:2]))
    return result.stdout

def cname(service):
    # client-A/B 컨테이너는 capstone-a- 접두어 없이 이름이 고정되어 있다(PR #33).
    return service if service.startswith("client-") else "capstone-a-" + service

def require(condition, label):
    if not condition:
        raise AssertionError(label)
    print("PASS " + label)

def main():
    expected = {
        "gateway": {"client_net", "server_net", "action_net"},
        "client-A": {"client_net"}, "client-B": {"client_net"},
        "caddy": {"server_net"}, "web": {"server_net"},
        "erp": {"server_net", "erp_db_net", "erp_control_net"}, "erp-db": {"erp_db_net"},
    }
    names = ["capstone-a_" + n for n in ("client_net", "server_net", "action_net", "erp_db_net", "erp_control_net")]
    nets = json.loads(docker("network", "inspect", *names))
    for net in nets:
        require(net["Internal"] and not net.get("EnableIPv6"), net["Name"] + " internal IPv4")
        require(not net.get("Options", {}).get("parent"), net["Name"] + " no physical parent")
        if net["Name"].endswith(("_client_net", "_server_net")):
            require(net["Driver"] == "macvlan" and net["Options"].get("macvlan_mode") == "bridge",
                    net["Name"] + " separate Macvlan L2")
        if net["Name"].endswith("_erp_control_net"):
            peers = {c["Name"]: c["IPv4Address"] for c in net.get("Containers", {}).values()}
            require(peers.get("capstone-a-erp") == "10.250.31.20/24"
                    and set(peers) <= {"capstone-a-erp", "capstone-soc-dashboard"}
                    and peers.get("capstone-soc-dashboard", "10.250.31.60/24") == "10.250.31.60/24",
                    "ERP control network restricted to ERP and dashboard")
    items = json.loads(docker("inspect", *[cname(s) for s in expected]))
    for item in items:
        service = item["Name"].removeprefix("/").removeprefix("capstone-a-")
        require(item["State"]["Running"], service + " running")
        require(set(item["NetworkSettings"]["Networks"]) == {"capstone-a_" + n for n in expected[service]},
                service + " exact network membership")
        cfg = item["HostConfig"]
        require(not cfg["Privileged"] and not cfg.get("PortBindings") and cfg["ReadonlyRootfs"],
                service + " no privilege/published ports; read-only root")
        require("ALL" in cfg.get("CapDrop", []) and "no-new-privileges:true" in cfg.get("SecurityOpt", []),
                service + " capability restrictions")
        require(cfg["NanoCpus"] > 0 and cfg["Memory"] > 0 and cfg["PidsLimit"] > 0,
                service + " resource limits")
        routes = docker("exec", cname(service), "ip", "route")
        require(not any(line.startswith("default") for line in routes.splitlines()), service + " no default route")
        if service in ("client-A", "client-B", "caddy", "web", "erp"):
            via = "172.28.10.2" if service.startswith("client-") else "172.28.20.2"
            require("172.28.0.0/16 via " + via in routes, service + " gateway route")
        if service.startswith("client-"):
            require(not cfg.get("CapAdd"), service + " cannot change route or craft raw packets")
    require(not docker("exec", "capstone-a-gateway", "iptables", "-S", "GW_BLOCK").count("-A "),
            "no leftover manual block")
    print("Network layout verified; HTTPS/block/recovery require verify_day3.sh.")

if __name__ == "__main__":
    try:
        main()
    except (AssertionError, RuntimeError, subprocess.TimeoutExpired) as exc:
        print("FAIL " + str(exc))
        sys.exit(1)
