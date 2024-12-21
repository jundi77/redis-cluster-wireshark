# redis-cluster-wireshark

I created a plugin for wireshark that may help in understanding how Redis node-to-node communicate. I specifically created this plugin for an exam in ITS Distributed System class for a study case on Redis Cluster, you can check the code used at: https://github.com/jundi77/eas-ds2024. Tested and used on Wireshark v4.4.1.

I mainly observe Redis code and see what do i need to parse and what is the bytes pattern used when transmitting the data. See related Redis code [here](https://github.com/redis/redis/blob/684077682e5826ab658da975c9536df1584b425f/src/cluster_legacy.c#L2694).

This plugin mainly see the default node-to-node default port at 16379. Adjust the script if you used different port, or help to expand functionality further by opening a pull requests! Have a good day.
