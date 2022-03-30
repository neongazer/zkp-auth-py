# zkp-auth-py
ZKP Protocol for Authentication in Python 3.7

It is using Chaum-Pedersen proof to prove the equality of exponents of two modular exponentiation with different bases.

## New Python Project Setup

### 1. Check you have Python 3.7 installed and available
```shell
python3.7 --version
pip3 --version
```

*If you do not have python3.7 then look for Python installer for your OS*

### 2. Clone project
```shell
git clone https://github.com/andrewboss/zkp-auth-py.git
cd zkp-auth-py
```

### 3. Install virtualenv python module
```shell
pip3 install --user virtualenv
```

### 4. Create virtual python environment
```shell
python3.7 -m virtualenv venv
```

### 5. Activate virtual environment
```shell
source venv/bin/activate
```

### 6. Install project modules
```shell
pip install --upgrade -r requirements.txt
```

### 7. Run unit tests:
```shell
Main integration test Prover with Verifier:
python -m unittest -v tests/sigma_protocols/chaum_pederson/test_prover_with_verifier.py
```
or all tests:
```shell
python -m unittest discover tests
```
