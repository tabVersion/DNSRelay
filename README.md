# dnsrelay

implementation of DNS relay

functions:
1. forwarding
2. blocking
3. cache

first the program reads a list of cache urls from file `url ip-address`  
when comes a request, it will check whether the requested url is in cache  
if so it will check whether the ip-address is `0.0.0.0`  
    if so, the request will be block  
    else return the cached ip-address   
otherwise, it will forward the request to remote server `8.8.8.8`
