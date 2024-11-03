from bleak import BleakScanner
import asyncio
import datetime
import signal
import platform
import struct
import csv
import os
from typing import Dict, Any

class BeaconScanner:
    def __init__(self):
        self.scanner = None
        self.is_running = True
        self.APPLE_COMPANY_ID = 0x004C
        self.GOOGLE_COMPANY_ID = 0x00AA
        
        # CSVファイルの設定
        self.timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        self.csv_filename = f"beacon_data_{self.timestamp}.csv"
        self.create_csv_file()
        
    def create_csv_file(self):
        """CSVファイルの作成とヘッダーの書き込み"""
        headers = [
            'timestamp',
            'device_address',
            'device_name',
            'rssi',
            'beacon_type',
            'company_id',
            'uuid',
            'major',
            'minor',
            'tx_power',
            'service_uuids',
            'frame_type',
            'raw_data'
        ]
        
        with open(self.csv_filename, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(headers)
        
        print(f"CSVファイルを作成しました: {self.csv_filename}")

    def write_to_csv(self, data: Dict[str, Any]):
        """データをCSVファイルに書き込む"""
        try:
            row = [
                data.get('timestamp', ''),
                data.get('device_address', ''),
                data.get('device_name', ''),
                data.get('rssi', ''),
                data.get('beacon_type', ''),
                data.get('company_id', ''),
                data.get('uuid', ''),
                data.get('major', ''),
                data.get('minor', ''),
                data.get('tx_power', ''),
                ','.join(data.get('service_uuids', [])),
                data.get('frame_type', ''),
                data.get('raw_data', '')
            ]
            
            with open(self.csv_filename, 'a', newline='') as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(row)
        except Exception as e:
            print(f"CSVファイルの書き込み中にエラーが発生: {e}")

    def parse_ibeacon(self, mfg_data: bytes) -> Dict[str, Any]:
        """iBeaconデータのパース"""
        try:
            if len(mfg_data) < 23:
                return None
            
            uuid_bytes = mfg_data[2:18]
            major = struct.unpack(">H", mfg_data[18:20])[0]
            minor = struct.unpack(">H", mfg_data[20:22])[0]
            tx_power = struct.unpack("b", mfg_data[22:23])[0]
            
            return {
                "beacon_type": "iBeacon",
                "uuid": '-'.join([
                    uuid_bytes[0:4].hex(),
                    uuid_bytes[4:6].hex(),
                    uuid_bytes[6:8].hex(),
                    uuid_bytes[8:10].hex(),
                    uuid_bytes[10:16].hex()
                ]),
                "major": major,
                "minor": minor,
                "tx_power": tx_power,
                "raw_data": mfg_data.hex()
            }
        except Exception:
            return None

    def parse_eddystone(self, service_data: bytes) -> Dict[str, Any]:
        """Eddystoneビーコンデータのパース"""
        try:
            frame_type = service_data[0]
            result = {
                "beacon_type": "Eddystone",
                "frame_type": hex(frame_type),
                "raw_data": service_data.hex()
            }
            
            if frame_type == 0x00:  # UID
                result.update({
                    "frame_type": "UID",
                    "tx_power": struct.unpack("b", service_data[1:2])[0],
                    "namespace": service_data[2:12].hex(),
                    "instance": service_data[12:18].hex()
                })
            elif frame_type == 0x10:  # URL
                result.update({
                    "frame_type": "URL",
                    "tx_power": struct.unpack("b", service_data[1:2])[0],
                })
            elif frame_type == 0x20:  # TLM
                result.update({
                    "frame_type": "TLM",
                    "battery_voltage": struct.unpack(">H", service_data[2:4])[0],
                    "temperature": struct.unpack(">h", service_data[4:6])[0] / 256.0,
                })
            
            return result
        except Exception:
            return None

    def parse_manufacturer_data(self, mfg_data: Dict[int, bytes]) -> Dict[str, Any]:
        """製造者固有データの解析"""
        result = {}
        for company_id, data in mfg_data.items():
            result["company_id"] = f"0x{company_id:04X}"
            
            if company_id == self.APPLE_COMPANY_ID:
                ibeacon_data = self.parse_ibeacon(data)
                if ibeacon_data:
                    result.update(ibeacon_data)
            else:
                result["raw_data"] = data.hex()
        return result

    async def detection_callback(self, device, advertisement_data):
        """デバイス検出時のコールバック関数"""
        current_time = datetime.datetime.now()
        
        # データの収集
        beacon_data = {
            'timestamp': current_time.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
            'device_address': device.address,
            'device_name': device.name or 'Unknown',
            'rssi': device.rssi,
            'service_uuids': advertisement_data.service_uuids or [],
        }
        
        # 製造者データの解析
        if advertisement_data.manufacturer_data:
            mfg_info = self.parse_manufacturer_data(advertisement_data.manufacturer_data)
            beacon_data.update(mfg_info)
        
        # Eddystoneデータの解析
        if advertisement_data.service_data:
            for uuid, data in advertisement_data.service_data.items():
                if "feaa" in str(uuid).lower():
                    eddystone_data = self.parse_eddystone(data)
                    if eddystone_data:
                        beacon_data.update(eddystone_data)
        
        # CSVに書き込み
        self.write_to_csv(beacon_data)
        
        # コンソール出力
        print(f"\n[{beacon_data['timestamp']}] ビーコン検出:")
        print(f"  デバイス: {beacon_data['device_name']} ({beacon_data['device_address']})")
        print(f"  RSSI: {beacon_data['rssi']}dBm")
        if 'beacon_type' in beacon_data:
            print(f"  タイプ: {beacon_data['beacon_type']}")
        if 'uuid' in beacon_data:
            print(f"  UUID: {beacon_data['uuid']}")
        if 'major' in beacon_data:
            print(f"  Major: {beacon_data['major']}")
            print(f"  Minor: {beacon_data['minor']}")

    async def cleanup(self):
        """クリーンアップ処理"""
        if self.scanner:
            try:
                print("\nスキャナーを停止中...")
                await self.scanner.stop()
                self.is_running = False
                print(f"スキャンを終了しました。データは {self.csv_filename} に保存されています")
            except Exception as e:
                print(f"スキャナー停止中にエラーが発生: {e}")

    async def run(self):
        """メインのスキャン処理"""
        try:
            print("ビーコンのスキャンを開始します...")
            print(f"データは {self.csv_filename} に保存されます")
            print("終了するには Ctrl+C を押してください")
            
            self.scanner = BleakScanner(self.detection_callback)
            
            while self.is_running:
                await self.scanner.start()
                await asyncio.sleep(5)  # 5秒間スキャン
                if self.is_running:
                    await self.scanner.stop()
                
        except Exception as e:
            print(f"\nエラーが発生しました: {e}")
        finally:
            await self.cleanup()

async def main():
    """メイン関数"""
    scanner = BeaconScanner()
    
    def signal_handler(signum, frame):
        print("\n終了シグナルを受信しました")
        scanner.is_running = False
        
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    await scanner.run()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nプログラムを終了します")