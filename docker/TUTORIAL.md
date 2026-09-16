# Check proper cvmUuid 
.phala/config

# build keystore 
####### old ./scripts/build_and_push_keystore.sh zavodil v1.0.3   # personal namespace, historical
./scripts/build_and_push_keystore_tee.sh outlayer v0.1.42

# deploy keystore to phala
cd docker
phala deploy --name outlayer-testnet-keystore --compose docker-compose.keystore-phala.yml --env-file .env.testnet-keystore-phala --vcpu 1 --memory 1G --disk-size 1G --kms-id phala-prod10

phala cvms create --name outlayer-testnet-keystore --compose ./docker-compose.keystore-phala.yml --env-file ./.env.testnet-keystore-phala  --vcpu 1 --memory 1G --disk-size 1G

# set KEYSTORE_BASE_URLS based on keystore deployment
/docker/.env.testnet-worker-phala

# build worker-only
./scripts/build_and_push_phala.sh outlayer v0.1.42 worker

# build worker-compiler 
./scripts/build_and_push_phala.sh outlayer v0.1.42 worker-compiler

# deploy worker to phala
cd docker 
phala deploy --name outlayer-testnet-worker --compose docker-compose.phala.yml --env-file .env.testnet-worker-phala --vcpu 1 --memory 1G --disk-size 2G --kms-id phala-prod10

# Compilation does not run in the enclave: the TEE workers execute only
# (COMPILATION_ENABLED=false). A separate worker compiles, and pins the image it
# compiles in by digest — see worker/.env.testnet.worker1.

# whitelist measurements after code updates
# use scripts/deploy_phala.sh which extracts all 5 TDX measurements (MRTD + RTMR0-3) automatically
# or extract manually from Phala attestation and call add_approved_measurements

near contract call-function as-transaction worker.outlayer.testnet add_approved_measurements json-args '{"measurements":{"mrtd":"...","rtmr0":"...","rtmr1":"...","rtmr2":"...","rtmr3":"..."}, "clear_others": true}' prepaid-gas '30.0 Tgas' attached-deposit '0 NEAR' sign-as owner.outlayer.testnet network-config testnet sign-with-keychain send

near contract call-function as-transaction dao.outlayer.testnet add_approved_measurements json-args '{"measurements":{"mrtd":"...","rtmr0":"...","rtmr1":"...","rtmr2":"...","rtmr3":"..."}, "clear_others": true}' prepaid-gas '30.0 Tgas' attached-deposit '0 NEAR' sign-as owner.outlayer.testnet network-config testnet sign-with-keychain send

# check whitelist
near contract call-function as-read-only worker.outlayer.testnet get_approved_measurements json-args {} network-config testnet now

# check logs
curl 'https://f53d94690545c6f6ea877f471482822f406bf29f-8090.dstack-pha-prod9.phala.network/logs/near-offshore-worker?since=0&until=0&follow=true&text=true&timestamps=true&bare=true'
