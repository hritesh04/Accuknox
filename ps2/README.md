### Problem Statement 2

    > Write an eBPF code to allow traffic only at a specific TCP port (default 4040) for a given process name (for e.g, "myprocess"). All the traffic to all other ports for only that process should be dropped.

##### Potential? way to the solution

    we can have a socket ebpf program which retreives the process name and puts the name into a map.

    The value from the map can then be access by a XDP ebpf program which checks for the tcp port and name if both matches then allow the packets to go else drop the packets