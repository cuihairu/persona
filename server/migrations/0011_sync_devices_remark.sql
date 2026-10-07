-- S4 设备面补强：sync_devices 增加自备注列。「仅改自己备注」由
-- PUT /sync/devices/remark 按令牌归属的设备名落 WHERE device_name = ?
-- 保证——不走路径参数，跨设备备注在接口形态上就不存在。空串 = 清除。
ALTER TABLE sync_devices ADD COLUMN remark TEXT NOT NULL DEFAULT '';
