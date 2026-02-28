#cat-output
give out in os root, all info in cat-output/README.md

#go-output
fix ./deploy.sh to 
    your:
        username
        hostname
        dir
    in my case:
        admin
        rpi
        /home/admin/execute
after run on rpi sudo ./ringdemo

get real traffic out in terminal

 
#web-output
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

DELETE localhost:8080/blacklist?Ipv4ToUnBlock

// WHITELIST -> skip IP in reading/any actions

POST localhost:8080/blacklist with body { "ip" : "Ipv4ToAddWhiteList"}

DELETE localhost:8080/blacklist?Ipv4ToRemoveFromWhiteList
