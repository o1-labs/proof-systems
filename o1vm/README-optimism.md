## Run infra for OP Sepolia on Ubuntu

Install the first dependencies:

```
sudo apt update
# chrony will ensure the system clock is up to date
sudo apt install build-essential git vim chrony ufw -y
```

Set up your firewall

```
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow OpenSSH
sudo ufw allow 8545
sudo ufw allow 8546
sudo ufw allow 8551
sudo ufw allow 30303
sudo ufw show added
sudo ufw enable
```

Set up a non-root user and its environment

```
sudo useradd validator
mkdir /validator
```

Set up go:

```
cd /validator
curl -OL https://go.dev/dl/go1.22.3.linux-amd64.tar.gz
sudo tar -C /usr/local -xvf go1.22.3.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.profile
source ~/.profile
```

Set up op-geth:

```
git clone https://github.com/ethereum-optimism/op-geth.git
cd op-geth
git checkout v1.101315.1 #or another more recent stable tag
make all
```

Set up op-node:

```
cd /validator
git clone https://github.com/ethereum-optimism/optimism.git
git checkout v1.7.6 #or another more recent stable tag
cd optimism/op-node
make op-node
```

Generate a JWT token:

```
cd /validator
mkdir infra-for-op && cd infra-for-op
openssl rand -hex 32 > jwt.txt
```

Generate genesis:

```
curl -o genesis.json -sL https://storage.googleapis.com/oplabs-network-data/Sepolia/genesis.json
../op-geth/build/bin/geth init --datadir="op-geth-data" genesis.json
```

Create the script `/validator/infra-for-op/op-geth-run.sh` to run OP geth

```
#!/bin/bash
SEQUENCER_URL="https://sepolia-sequencer.optimism.io/"

DATADIR="/validator/infra-for-optimism/data"
JWT_TOKEN="/validator/infra-for-optimism/jwt.txt"
HTTP_PORT=8545
WS_PORT=8546
AUTHRPC_PORT=8551
PORT=30303

/validator/op-geth/build/bin/geth \
        --datadir=${DATADIR} \
	--verbosity=3 \
        --http \
        --http.corsdomain="*" \
        --http.vhosts="*" \
        --http.addr 0.0.0.0 \
        --http.port ${HTTP_PORT} \
        --http.api web3,debug,eth,txpool,net,engine \
        --ws \
        --ws.addr "0.0.0.0" \
        --ws.port ${WS_PORT} \
        --ws.origins="*" \
        --ws.api=debug,eth,txpool,net,engine \
        --authrpc.vhosts="*" \
        --authrpc.addr "0.0.0.0" \
        --authrpc.port ${AUTHRPC_PORT} \
        --authrpc.jwtsecret=${JWT_TOKEN} \
        --syncmode=full \
        --op-network=op-sepolia \
        --rollup.sequencerhttp=$SEQUENCER_URL \
        --port=${PORT} \
        --discovery.port=${PORT} \
        --gcmode=archive
```

Create the service `/etc/systemd/system/op-geth.service`

```
[Unit]
Description=OP geth service

[Service]
Type=simple
User=validator
Restart=always
ExecStart=/validator/infra-for-optimism/op-geth-run.sh

[Install]
WantedBy=default.target
```

Enable the op-geth service

```
sudo systemctl enable op-geth
```

Create the folder to store op-node files:

```
mkdir /validator/infra-for-optimism/op-node-data
```

Create the script `/validator/infra-for-op/op-node-run.sh` to run the OP node:

```
#!/bin/bash
L1_RPC_URL=https://ethereum-sepolia-rpc.publicnode.com
L1_RPC_KIND=standard
L1_BEACON_URL=https://ethereum-sepolia-beacon-api.publicnode.com
L2_PORT=8551
LISTENING_ADDR="0.0.0.0"

JWT_FILE="/validator/infra-for-optimism/jwt.txt"

cd /validator/infra-for-optimism/op-node-data

/validator/optimism/op-node/bin/op-node \
    --l1=${L1_RPC_URL}  \
    --l1.rpckind=${L1_RPC_KIND} \
    --l1.beacon=${L1_BEACON_URL} \
    --l2=ws://localhost:${L2_PORT} \
    --l2.jwt-secret="${JWT_FILE}" \
    --network=op-sepolia \
    --syncmode=execution-layer
```

Create the service `/etc/systemd/system/op-node.service`

```
[Unit]
Description=OP node service

[Service]
Type=simple
Restart=on-failure
RestartSec=5s
User=validator
ExecStart=/validator/infra-for-optimism/op-node-run.sh

[Install]
WantedBy=multi-user.target
```

Enable the op-node service

```
sudo systemctl enable op-node
```

Make sure the user `validator` can run the services smoothly:

```
chown -R validator:validator /validator
loginctl enable-linger validator
```

Start and check the op-geth service

```
sudo systemctl start op-geth
journalctl -u op-geth -n 20 -f
```

Start and check the op-node service

```
sudo systemctl start op-node
journalctl -u op-node -n 20 -f
```
