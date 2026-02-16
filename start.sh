#!/bin/bash

# Start ZAP in daemon mode on port 8090
echo "Starting ZAP daemon..."
/opt/zap/zap.sh -daemon -host 127.0.0.1 -port 8090 -config api.disablekey=true &

# Wait for ZAP to start
echo "Waiting for ZAP to initialize..."
timeout 60s bash -c 'until curl -s http://127.0.0.1:8090/JSON/core/view/version/; do sleep 2; done'

# Check if ZAP started successfully
if [ $? -ne 0 ]; then
  echo "ZAP failed to start."
  exit 1
fi

echo "ZAP started successfully."

# Start Flask app using Gunicorn
# Bind to 0.0.0.0:$PORT (Render provides PORT environment variable)
echo "Starting Flask app on port $PORT..."
exec gunicorn app:app --bind 0.0.0.0:$PORT
