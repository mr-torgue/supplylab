# install broker
sudo apt update && sudo apt upgrade
sudo apt install -y mosquitto mosquitto-clients
sudo systemctl enable mosquitto.service
# install a client 
curl -L -O https://www.emqx.com/en/downloads/MQTTX/v1.9.10/MQTTX_1.9.10_arm64.deb
sudo apt install ./MQTTX_1.9.10_arm64.deb
rm MQTTX_1.9.10_arm64.deb
sudo cp supplylab_mqtt.conf /etc/mosquitto/conf.d/
