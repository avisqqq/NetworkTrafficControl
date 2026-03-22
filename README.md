fix ./deploy.sh to 
    your:
        username
        hostname
        dir
    in my case:
        admin
        rpi
        /home/admin/execute
after run on rpi sudo ./ntc


localhost:8080 -> GUI Web Pang Reading /events
// READING ALL EVENTS

GET localhost:8080/events -> raw messanges (probably not working in your browser need terminal/bruno/yaak)

// BLACKLIST block ip in reading/any actions

POST localhost:8080/blacklist with body { "ip" : "Ipv4ToBlock"}

DELETE localhost:8080/blacklist?ip=Ipv4ToUnBlock

GET localhost:8080/whitelist -> return whitelist

// WHITELIST -> skip IP in reading/any actions

POST localhost:8080/whitelist with body { "ip" : "Ipv4ToAddWhiteList"}

DELETE localhost:8080/whitelist?ip=Ipv4ToRemoveFromWhiteList

GET localhost:8080/whitelist -> return whitelist 
