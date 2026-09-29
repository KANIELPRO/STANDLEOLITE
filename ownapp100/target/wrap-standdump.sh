#!/system/bin/sh
export LD_PRELOAD=/data/local/tmp/libapidump.so
exec /system/bin/app_process64 "$@"
