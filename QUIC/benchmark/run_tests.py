import subprocess
import time

# VPN endpoint IP (must be reachable inside VPN tunnel)
VERSION = "QUIC"
VPN_TARGET_IP = "192.168.60.7"
VPN_CLIENT_CONTAINER = f"{VERSION}-client-10.9.0.5"
VPN_SERVER_CONTAINER = f"{VERSION}-server-router"
PRIVATE_HOST_CONTAINER = f"{VERSION}-host-192.168.60.7"

def run_cmd(cmd, capture_output=False):
    print(f"\n>>> Running: {cmd}")
    return subprocess.run(cmd, shell=True, text=True, capture_output=capture_output)

def run_ping_test():
    print("\nRunning ping test through VPN")
    run_cmd(f'docker exec {VPN_CLIENT_CONTAINER} ping -c 5 {VPN_TARGET_IP}')

def run_iperf_test():
    print("\nRunning iperf3 throughput test")

    # Start iperf3 server in Host1 container
    run_cmd(f'docker exec {PRIVATE_HOST_CONTAINER} pkill iperf3 || true')
    run_cmd(f'docker exec -d {PRIVATE_HOST_CONTAINER} iperf3 -s')

    # Run client test
    time.sleep(1)  # Wait for server to spin up
    run_cmd(f'docker exec {VPN_CLIENT_CONTAINER} iperf3 -c {VPN_TARGET_IP} -t 10')

def run_concurrent_load():
    print("\nSimulating concurrent ping + iperf3 load")

    # Run long ping in background
    ping_proc = subprocess.Popen(
        f'docker exec {VPN_CLIENT_CONTAINER} ping -i 0.2 -c 20 {VPN_TARGET_IP}',
        shell=True
    )

    try:
        # Run iperf3 during ping
        run_cmd(f'docker exec {VPN_CLIENT_CONTAINER} iperf3 -c {VPN_TARGET_IP} -t 5')
    finally:
        ping_proc.terminate()

def check_cpu_memory():
    print("\nChecking server CPU and memory usage during idle state:")
    run_cmd(f'docker exec {VPN_SERVER_CONTAINER} top -b -n1 | head -15')

def main():
    print("Starting VPN Benchmarking")

    check_cpu_memory()
    run_ping_test()
    run_iperf_test()
    run_concurrent_load()

    print("\nBenchmark Complete")

if __name__ == "__main__":
    main()
