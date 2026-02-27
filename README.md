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

GET localhost:8080/events -> raw messanges (probably not working in your browser need terminal/bruno/yaak)

POST localhost:8080/blacklist with body { "ip" : "<Ipv4ToBlock>"}

DELETE localhost:8080/blacklist?<Ipv4ToBlock>
