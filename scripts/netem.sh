sudo tc qdisc del dev docker0 root
sudo tc qdisc add dev docker0 root netem loss 0.08%