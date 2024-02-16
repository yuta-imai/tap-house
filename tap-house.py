import time
import socket
import boto3
from botocore.config import Config
import concurrent.futures
from bcc import BPF

config = Config(
    region_name = 'ap-northeast-1'
)
kinesis_client = boto3.client('kinesis',config=config)

# BPFプログラムの初期化とアタッチ（前述のコードを使用）


def send_to_kinesis(stream_name, data):
    print(data)
    
    try:
        response = kinesis_client.put_record(
            StreamName=stream_name,
            Data=data,
            PartitionKey='partition_key'
        )
        return response
    except boto3.exceptions.Boto3Error as e:
        print(f"Error sending data to Kinesis: {e}")
        return None

def main():

    # Load eBPF program
    bpf = BPF(src_file="tap-house.c")

    # Attach eBPF program to a network interface (e.g., eth0)
    device = "eth0"
    bpf.attach_xdp(device, bpf.load_func("gre_aggregate_filter", BPF.XDP))

    print(f"XDP program attached to {device}.")

    # Kinesisストリーム名の設定

    stream_name = 'factory-tap-house'

    # ThreadPoolExecutorを用いた非同期処理のセットアップ
    with concurrent.futures.ThreadPoolExecutor() as executor:
        while True:
            futures = []
            packet_stats = bpf["packet_stats"]
            for key, value in packet_stats.items():
                # Format data for sending
                src_ip = socket.inet_ntoa(key.src_ip.to_bytes(4,byteorder='little'))
                dst_ip = socket.inet_ntoa(key.dst_ip.to_bytes(4,byteorder='little'))
                data = {
                    "protocol": key.protocol,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "payload_len_total": value.payload_len_total,
                    "packet_count": value.packet_count
                }
                # 非同期タスクのスケジューリング
                future = executor.submit(send_to_kinesis, stream_name, str(data))
                futures.append(future)

                # Delete the key from the map to reset the statistics
                packet_stats.pop(key, None)

            # 非同期タスクの完了を待機
            for future in futures:
                future.result()

            time.sleep(3)  # Wait for a minute before the next check


if __name__ == "__main__":
    main()  