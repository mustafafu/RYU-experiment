# RYU-experiment
Data Center and Cloud Computing Lab experiment with RYU controller


# Login to the geni node
```
ssh -p Port# NetID@**.instageni.**.**
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



Clone the repository
```
git clone https://github.com/mustafafu/RYU-experiment.git
```



# RYU: if error output in use
kill the process with ovs-testcontrol
port 6653
```
sudo netstat -nltp
sudo kill 28091
```
Kill ipv6 so its not confused
sudo sysctl net.ipv6.conf.all.disable_ipv6=1
sudo sysctl net.ipv6.conf.default.disable_ipv6=1


# Run the simple switch
In one terminal start mininet and use source cli_init.txt to stop ipv6
```
sudo mn --custom topology.py --topo mytopo --mac --switch ovsk,protocols=OpenFlow13 --controller remote
```

Once mininet starts, run cli_init to stop ipv6. 

```
source cli_init.txt
```
where the inside of cli_init.txt is as follows

```
h1 sysctl net.ipv6.conf.all.disable_ipv6=1
h2 sysctl net.ipv6.conf.all.disable_ipv6=1
h3 sysctl net.ipv6.conf.all.disable_ipv6=1
h4 sysctl net.ipv6.conf.all.disable_ipv6=1
```

in other terminal start the controller app.

```
ryu-manager --verbose ~/RYU-experiment/mfo254.py
```

## Getting terminals to mininet hosts

Use mininet ```dump``` command to get PIDs of the hosts. 
In a new terminal.
```
sudo mnexec -a [PID] bash
```


## Generate HTTP traffic

In server:
```
iperf -s -p 80
```
In client
```
iperf -c 10.0.0.[S] -p 80
```

## Check the flow rules
```
sudo ovs-ofctl --protocols=OpenFlow13 dump-flows s1
```
