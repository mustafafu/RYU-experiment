# RYU-experiment
Data Center and Cloud Computing Lab experiment with RYU controller


# Login to the geni node
```
ssh -p 26410 mfo254@pc1.instageni.uvm.edu
```
# Update and upgrade packages in the VM
```
sudo apt-get update
sudo apt-get upgrade -y
```

# Install mininet and test
```
sudo apt-get install mininet			mfo254@node-0:~$ mn --version
												2.2.2
```

```
sudo mn --switch ovsbr --test pingall
echo py sys.version | sudo mn -v output
```

```
sudo apt-get install openvswitch-testcontroller
```

# Install RYU dependencies
```
sudo apt install gcc python-dev libffi-dev libssl-dev libxml2-dev libxslt1-dev zlib1g-dev
```

# Install RYU
```
sudo apt install python3-ryu
```

Check version
```
ryu --version
```


# The Experiment
