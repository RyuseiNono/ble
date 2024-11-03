from bleak import BleakScanner
import asyncio
import datetime
import signal
import platform
import struct
from typing import Dict, Any

class BeaconScanner:
    def __init__(self):
        self.scanner = None
        self.is_running = True
        # iBeaconの会社識別子（Apple）
        self.APPLE_COMPANY_ID = 0x004C
        # Eddystoneの会社識別子（Google）
        self.GOOGLE_COMPANY_ID = 0x00AA
        
    def parse_ibeacon(self, mfg_data: bytes) -> Dict[str, Any]:
        """iBeaconデータのパース"""
        try:
            # iBeaconのデータ構造をパース
            ibeacon_prefix = mfg_data[0:2]
            if len(mfg_data) < 23:  # iBeaconの最小データ長
                return None
            
            uuid_bytes = mfg_data[2:18]
            major = struct.unpack(">H", mfg_data[18:20])[0]
            minor = struct.unpack(">H", mfg_data[20:22])[0]
            tx_power = struct.unpack("b", mfg_data[22:23])[0]
            
            return {
                "type": "iBeacon",
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
                "type": "Eddystone",
                "frame_type": hex(frame_type),
                "raw_data": service_data.hex()
            }
            
            if frame_type == 0x00:  # UID frame
                result.update({
                    "frame_type_name": "UID",
                    "tx_power": struct.unpack("b", service_data[1:2])[0],
                    "namespace": service_data[2:12].hex(),
                    "instance": service_data[12:18].hex()
                })
            elif frame_type == 0x10:  # URL frame
                result.update({
                    "frame_type_name": "URL",
                    "tx_power": struct.unpack("b", service_data[1:2])[0],
                    "url_scheme": service_data[2],
                    "encoded_url": service_data[3:].hex()
                })
            elif frame_type == 0x20:  # TLM frame
                result.update({
                    "frame_type_name": "TLM",
                    "version": service_data[1],
                    "battery_voltage": struct.unpack(">H", service_data[2:4])[0],
                    "temperature": struct.unpack(">h", service_data[4:6])[0] / 256.0,
                    "advertising_count": struct.unpack(">I", service_data[6:10])[0],
                    "seconds_since_boot": struct.unpack(">I", service_data[10:14])[0]
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
        current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        
        print(f"\n{'='*80}")
        print(f"[{current_time}] ビーコン検出:")
        print(f"{'='*80}")
        
        # 基本情報
        print(f"デバイス情報:")
        print(f"  アドレス: {device.address}")
        print(f"  デバイス名: {device.name or '不明'}")
        print(f"  RSSI: {device.rssi}dBm")
        
        # 製造者データの解析
        if advertisement_data.manufacturer_data:
            print("\n製造者固有データ:")
            mfg_info = self.parse_manufacturer_data(advertisement_data.manufacturer_data)
            for key, value in mfg_info.items():
                print(f"  {key}: {value}")
        
        # サービスデータの解析
        if advertisement_data.service_data:
            print("\nサービスデータ:")
            for uuid, data in advertisement_data.service_data.items():
                print(f"  UUID: {uuid}")
                # Eddystoneビーコンの検出
                if "feaa" in str(uuid).lower():  # Eddystone service UUID
                    eddystone_data = self.parse_eddystone(data)
                    if eddystone_data:
                        for key, value in eddystone_data.items():
                            print(f"    {key}: {value}")
                else:
                    print(f"    データ: {data.hex()}")
        
        # サービスUUID
        if advertisement_data.service_uuids:
            print("\nサービスUUID:")
            for uuid in advertisement_data.service_uuids:
                print(f"  {uuid}")
        
        # 送信出力とアドバタイジング間隔
        print(f"\n追加情報:")
        if hasattr(advertisement_data, 'tx_power'):
            print(f"  送信出力: {advertisement_data.tx_power or '不明'} dBm")
        
        print(f"  プラットフォーム: {platform.system()}")
        print(f"{'='*80}\n")

    async def cleanup(self):
        """クリーンアップ処理"""
        if self.scanner:
            try:
                print("\nスキャナーを停止中...")
                await self.scanner.stop()
                self.is_running = False
                print("スキャナーを正常に停止しました")
            except Exception as e:
                print(f"スキャナー停止中にエラーが発生: {e}")

    async def run(self):
        """メインのスキャン処理"""
        try:
            print("ビーコンのスキャンを開始します...")
            print("注意: macOSの場合は「Bluetooth」の権限を許可してください")
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