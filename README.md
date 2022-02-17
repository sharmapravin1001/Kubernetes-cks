Total Question = 15
 Exam Time = 2 hours
 
 
 
 Refer the github recommendation for CKS exam :
 
 https://github.com/walidshaari/Certified-Kubernetes-Security-Specialist
 https://github.com/kodekloudhub/certified-kubernetes-security-specialist-cks-course
 https://github.com/ggnanasekaran77/cks-exam-tips



 Lab Practice:
 [1] ACloudGuru Mock Lab [Go with 7 days trail [Hand-on-Labs search for "CKS" , there are 12 questions] --[Practice minimum 5 times]
 [2] kodekloud Lab --[Practice minimum 5 times]
 

 

 Security in Kubernetes is based out on 4C concepts:
 
 [1] Cloud [DataCentre, Network, Services]
 [2] Cluster [Authentication, Autherization, Admission Controller, Network Policy, Ingress]
 [3] Container [Restrict Images, Supply Chain, Privileged Container, Sandboxing, docker] -Minimizing Microservice vulnerabilities 
 [4] Code [Code Security best practices]
 ================================
 
 ================================
 During the CKS exam, candidates may:
 ================================
 Kubernetes Documentation: 
 https://kubernetes.io/docs/ and their subdomains
 https://github.com/kubernetes/ and their subdomains
 https://kubernetes.io/blog/ and their subdomains
 This includes all available language translations of these pages (e.g. https://kubernetes.io/zh/docs/)
 
 Tools:
 Trivy documentation https://aquasecurity.github.io/trivy/
 Sysdig documentation https://docs.sysdig.com/
 Falco documentation https://falco.org/docs/
 This includes all available language translations of these pages (e.g. https://falco.org/zh/docs/)
 App Armor:
 Documentation https://gitlab.com/apparmor/apparmor/-/wikis/Documentation
 ================================
 
 =============
 kube bench:
 ============= 
 kube bench is the tool from aqua security which check if the kuberenetes is deployed as per best security practices.
 
 kube bench can be deployed as docker container, pod in k8s cluster, installed as kube bench binaries , compile from source
 
 
 
 ==========================<end><end><end><end><end><end><end><end><end>
 kubelet security <start>:
 ==========================
 https://kodekloud.com/topic/kubelet-security/
 
 -- kubelet register the node, create pod and monitor node and pods 
 
 [1] Execue the following on the node to checkout the kublete configuration :
 # ps -aux|grep kubelet
 
 Grep the kubelet-config.yaml location and look out the following:
 -- /var/lib/kubelet/config.yaml [Kind: KubeletConfiguration]
 
 
 [2] kubelet support 2 ports:
 
 10250 - Serves API that allow full access [By default it allows but it can be changed].
 10255 - Serves API that allow unatenticated read-only access.
 
 There is big security risk, anyone know the IP address of host can run the following commands and get the information :
 # curl -sk https://localhost:10250/pods/
 # curl -sk https://localhost:10250/logs/syslog
 # curl -sk https://localhost:10255/metrics
 
 -----------------------------------------------------------
 |-- How to protect the kubelet behaviour to secure it ???? |
 ------------------------------------------------------------
 -- Generally for security there are 2 main pillars. Any request that come to kubelet first get authenticated and then authorized. 
 
 Authentication -- ensure if the user/request have access to the API
 Autherization -- what area that user have access and what they can perform 
 
 --------------------
 | [1] Authorization: |
 --------------------
 Supported authentication methods :
 [a] Certificate[x509]
 [b] API Bearer Tokens 
 
 [Note: By default, kubelet allow all request on 10250 port with anonymous user and group unautenticated.]
 To fix the security risk, edit the kubelet-config.yaml file and include the following
 [1.a] Modify the kubelet-config.yaml and include the following:
 Kind: KubeletConfiguration
 "authentication:"
 x509:
 clientCAFile: /path/to/ca.cert 
 [1.b] Modify the kublet-config.yaml and include the following:
 Kind: KubeletConfiguration
 "authentication:"
 anonymous:
 enabled: false
 After making the above changes, command to reach acces the pod from api, it will change to the following [ include the kublet client certificate configured in kube API server config file]
 # curl -sk https://localhost:10250/pods/ --key kubelet-key.pem --cert kubelet-cert.pem
 
 -------------------- 
 |[2] Authentication:|
 --------------------
 Note: By default, kubelet allow all requests authenticated automatically. 
 To fix the security risk, edit the kubelet-config.yaml file and include the following:
 [2.a] Modify the kublet-config.yaml and include the following:
 Kind: KubeletConfiguration
 "authentication:"
 mode: Webhook
 
 [2.b] Modify the kublet-config.yaml and include the following to disable the kubelet serving request on 10255 [set readonlyPort=0] so no one access it. [To enable [readonlyPort=10255] 
 Kind: KubeletConfiguration
 readOnlyPort: 0
 
 ====================
 kubelet security <end>
 ====================
 
 
 ============
 Ingress :
 ============
 
 ----Practice Network Policy and Ingress again for CKS
 
 Ingress rewrites testing -- more info is available here 
 https://kodekloud.com/topic/ingress-annotations-and-rewrite-target-2/
 
 
 
 =========================
 docker configuration:
 =========================
 docker installation includes the running of docker daemon on /var/run/docker.sock (unix socket). The docker daemon runs on host where docker run and docker is accessible via docker cli.
 
 If the docker host is server in located on cloud Or customer on-premises DC then you need to expose the docker daemon on docker ports 
 There are 2 docker ports that from which docker can be exposed so that end users from their laptop can access the docker tcp://host:port.
 
 docker ports are : 
 2375 [unencrypted traffic] 
 2376 [encrypted traffic]
 
 Note: dockerd is method of starting the docker manually. Other ways of starting the docker as services as "systemctl start docker"
 
 dockerd --host=tcp://<docker-host-ip>:2375
 
 # dockerd --debug=true --host=tcp://<docker-host-ip>:2376 tls=true tlscert=/var/docker/server.pem tlskey=/var/docker/serverkey.pem
 
 Or 
 
 # dockerd 
 
 Note: The above dockerd will work only if you have configured the configuration in yaml file located on /etc/docker/daemon.json [ dockerd looks for file in this location]
 
 --cat /etc/docker/daemon.json
 {
 "debug"=true,
 "host"=[tcp://<docker-host-ip>:2376],
 "tlsverify"=true,
 "tlscert"=/var/docker/server.pem, 
 "tlskey"=/var/docker/serverkey.pem,
 "tlscert"=/var/docker/caserver.pem
 }
 
 --From the local laptop accessing the docker ,need to export the variable first 
 # export DOCKER_TLS_verify=true or [docker --tlsverify=true]
 # export DOCKER_HOST="tcp://<docker-host-ip>:2376"
 # docker --tlsverify=true --tlscert=/user/parvesha/client.pem --tlskey=/user/parvesha/clientkey.pem --tlscert=/user/parvesha/ca.cert ps
 
 Note: remember to create the client side and server side certificate along with ca certificate for end to end tls encryption.
 
 certificate argument while running the docker command from the local laptop can be avoided, if you copy the certificate to :
 # $HOME/.docker
 # ls
 clientkey.pem client.pem cacert.pem
 =========================================
 
 
 
 ====================
 System Hardening:
 ====================
 
 ----------------------------
 --[1] Limit Node Access:
 ----------------------------
 
 /etc/passwd : contains username
 /etc/shawdow : contains password 
 /etc/group : contains user group
 
 To check the details of user who logged in:
 # id
 
 To check name of user logged in:
 # who
 
 To check the list the last time users logged in to the system:
 #last
 
 ---------------------
 Based on above info, user can be disabled or deleted.
 ---------------------
 # usermod -s /bin/nologin parvesha
 # grep -i parvesha /etc/passwd
 parvesha:x:1001:1001:/home/parvesha:/bin/nologin
 
 Or 
 #userdel parvesha
 
 ----------------
 If the user has been assigned to multiple group:
 ----------------
 # id parvesha
 uid=1001(parvesha) gid=1001(parvesha) groups=1001(parvesha),1000(admin)
 
 # deluser parvesha admin
 Removing user parvesha from group 'admin'
 
 # id parvesha
 uid=1001(parvesha) gid=1001(parvesha) groups=1001(parvesha)
 --------------------------------
 
 ---------------
 Restrict Kernel Modules:
 ---------------
 
 ---------------
 --To load the kernel modules: 
 ---------------
 # modprobe <module name> 
 e.g.
 # modprobe pcspkr
 ---------------
 
 ---------------
 --To list all the modules loaded into the kernel on the host/node
 ---------------
 #lsmod
 ---------------
 
 ---------------
 --To blacklist the module which are not in used, create conf file of any name inside below path
 ---------------
 blacklist.conf is just custom name, you can choose any name but path/location has to be same [/etc/modprobe.d]
 
 for e.g , we are blacklisting the sctp module
 # cat /etc/modprobe.d/blacklist.conf
 blacklist sctp
 
 Restart the node/host to ensure that it doesn appear in "lsmod" output
 #shutdown -r now 
 #lsmod |grep sctp
 =============================
 
 
 
 =============================
 Identify and Disabled the open ports which are not in used :
 =============================
 [1] Grep the port using netstat an |grep LISTEN
 
 [2] Check the services running on the host , usually they are on /etc/services and grep the port you got it from above netstat command
 on Ubantu, check the /etc/services|grep -w 53
 =============================
 
 
 =============================
 Firewall in linux managed with the following :
 =============================
 [1] iptables 
 [2] ufw 
 
 ----------
 Linux ufw [uncomplicated firewall] :
 ----------
 There are many services along with the ports are keep running on linux, therefore, it would be good to manage those services via ufw to control the vulnerabilities.
 ufw is simple and easy interface to apply the firewall rules 
 
 start with following 
 - Use netstat to look out for the port which are listening.
 # netstat -an|grep -w LISTEN
 tcp 0 0.0.0.0:22 0.0.0.0:* LISTEN
 tcp 0 0.0.0.0:80 0.0.0.0:* LISTEN
 tcp 0 0.0.0.0:8080 0.0.0.0:* LISTEN
 
 Considering above, we just need ssh[22] and http[80] port to be only port to be allowed, port 8080 should be blocked.
 # apt update 
 # apt install ufw
 # systemctl enable ufw
 # ufw status 
 Status: Inactive 
 
 #Define default rule, considering there are no restrication for outpgoing on your app server, its only incoming port 80,22 should be allowed.
 
 #ufw default allow outgoing
 #ufw default deny incoming
 
 - Allowing the incoming connection from jump server[IP=172.16.238.5 ] on app server 
 #ufw allow from 172.16.238.5 to any port 22 proto tcp
 #ufw allow from 172.16.238.5 to any port 80 proto tcp
 # ufw deny 8080
 # ufw enable [make sure all rules are added]
 # ufw status 
 # ufw delete deny 8080 
 
 # ufw status 
 Status: active
 To Action From
 --- --------- -------------
 22/tcp Allow 172.16.238.5 -->1
 80/tcp Allow 172.16.238.5 -->2
 8080 Deny Anywhere -->3
 
 # ufw delete 3
 Deleting deny 8080 
 Proceed with operation (y|n) ?
 
 
 Follow the steps in chronolical order:
 1. systemctl disable ufw
 2. Setup the firewall rules for services.
 3. systemctl enabled ufw
 
 # systemctl ufw status
 =============================
 
 
 ===========================
 seccomp in kubernetes/docker:
 ===========================
 First , to trace the system call, linux has tool called strace.
 for e.g. 
 # strace touch /tmp/abc.log
 # strace -c touch /tmp/abc.log 
 
 
 seccomp = secure computing 
 
 It's linux kernel feature that can be used to sandbox application to only use the system call that they need. Its all about limiting the system call that application can use of. 
 
 In reality , application running on linux host make use of 435 system calls which can cause vulnerabilities to the system. First your application 
 need to be traced using the strace command to know what system call they are making then application can be restricted to those system call and this can be implemented 
 via seccomp.
 
 --To check if secomp is enabled. check the ouput for value of (CONFIG_SECCOMP)
 #grep -i seccomp /boot/config-$(uname-r)
 CONFIG_SECCOMP=y
 
 SECCOMP can operate on 3 modes. 
 Mode 0 Disabled 
 Mode 1 Enabled [but in STRICT mode [It restrict all except read, write,exit,]
 Mode 2 Filtered 
 
 If the host kernel is seccomp enable,docker container automaticall inherit the seccomp profile and apply the restriction.
 
 ------------------
 SECCOMP profile is made of 3 elements, they are normally declared in in json and being refered in kubernetes manifest file with pods
 ------------------
 architecture : x86_32bit, x86_64_bit
 syscall names : array of syscall 
 action : allow or deny them 
 default behaviour of profile : SCMP_ACT_ERRNO or SCMP_ACT_ALLOW
 
 --------
 seccomp in docker :
 --------
 docker run -it --rm -security-opt seccomp=/root/custom.json docker/whalesay /bin/sh
 
 cat /root/custom.json
 {
 "defaultAction": SCMP_ACT_ERRNO
 "architectures": [
 "SCMP_ARCH_X86_64",
 "SCMP_ARCH_X86_32"
 ],
 "syscalls": [
 {
 "names": [
 "arch_prctl",
 "brk"
 "mkdir"
 "close"
 "clone"
 ]
 ],
 "action": "SCMP_ACT_ALLOW
 }
 
 # To disable the seccomp profile completely from the docker , although not recommended
 docker run -it --rm -security-opt seccomp=unconfined docker/whalesay /bin/sh 
 
 
 
 }
 
 --------
 seccomp in kubernetes 
 --------
 Default location of seccomp profile used by kubernetes = /var/lib/kubelet/secccomp/profiles/<file-name>.json
 
 cat ~/profiles/<file-name>.json
 {
 "defaultAction": "SCMP_ACT_LOG"
 }
 
 
 -- In kubernetes pod file [include the seccomp as shown below]:
 
 apiVersion: v1
 kind: Pod 
 metadata:
 name: nginx
 
 spec: 
 securityContext:
 seccompProfile:
 type: Localhost
 localhostProfile: profile/audit.json
 
 containers:
 - command: ["sh","-c","sleep 100"]
 -----------
 
 This profile help to dump all the audti logs of the system call that application makes then based on the audit log, create the list of final system call that your application needs
 and include them in custom.json 
 
 Or you can use the 3rd party tools like tracee which also gather and help analyze the system call that your application needs and finnalye create the custom system calls.
 
 apiVersion: v1
 kind: Pod 
 metadata:
 name: nginx
 
 spec: 
 securityContext:
 seccompProfile:
 type: Localhost
 localhostProfile: profile/custom.json
 
 containers:
 - command: ["sh","-c","sleep 100"]
 =============================
 
 
 
 ==========
 tracee :
 ==========
 Use tracee tool to analyze the system call made by any newly container 
 
 docker run --name tracee --rm --privileged -pid=host -v /lib/modules:/lib/modules/:ro -v /usr/src:/usr/src:ro -v /tmp/tracee:/tmp/tracee aquasec/tracee:4.0 -trace container=new
 
 
 Exam Tip:
 
 You maye asked to copy the default seccomp profile and copy them to all the nodes . modify it and create the pods using this seccomp profile
 =============================
 
 
 ----------
 AppArmor profile [short form of AppArmor = aa] :
 ----------
 AppArmor profile are more granular then seccomp. for e.e.g how can we prevent program/application to write to filesystem or directly 
 
 AppArmor is linux based feature used to limit/control the resource usage by program allowing the profile which are more granular than seccomp.
 
 -- To check if the apparmor module is loaded to kernel :
 # cat /sys/modules/apparmor/parameters/enabled
 Y
 
 -- To check the apparmor profile is loaded in the kernel
 # cat /sys/kernel/security/apparmor/profiles
 /sbin/dhclient (enforce)
 /usr/sbin/ntpd (enforce)
 
 # aa-status -- to check the status of aa profile
 
 --How to create AppArmor profile (name=apparmor-deny-write) which has rule to all access to entire file system but deny write access root file system
 profile apparmor-deny-write flags=(attach_disconnected) 
 {
 file,
 deny /**,w,
 }
 
 
 AppArmor profile can be loaded into kernel in 3 diff modes :
 [1] enforce [It will monitor and enforce the rule on application ]
 [2] complain [It will allow the application to perform task without any restrication, and it will log the events]
 [3] unconfined [It will allow the application to perform task without any restrication but will not log the events]
 
 --------------------
 Installation of AppArmor tools:
 --------------------
 
 # apt install apparmor-utils
 # aa-genprof /root/add_data.sh
 
 # apparmor_parser /etc/apparmor.d/root.add_data.sh
 #
 If the above apparmor_parser returned nothing then profile is sucessfully loaded.
 
 To disable the same profile 
 # apparmor_parser -R /etc/apparmor.d/root.add_data.sh
 # ln -s /etc/apparmor.d/root.add_data.sh /etc/apparmor.d/disable
 =============================
 
 --How to create AppArmor profile (name=apparmor-deny-write) which has rule to all access to entire file system but deny write access root file system
 profile apparmor-deny-write flags=(attach_disconnected) 
 {
 file,
 deny /**,w,
 }
 
 -------------------
 How to setup the AppArmor in kubernetes pod:
 -------------------
 [1] Enable the AppArmor kernel module on host
 # systemctl status apparmor
 # systemctl enable apparmor
 # systemctl start apparmor
 
 [2] Load the AppArmor profile in kernel on the host[Profile name = apparmor-deny-write created with syntax shown above]
 # apparmor_parser /etc/apparmor.d/apparmor-deny-write
 
 
 [3] aa-status on the host [Check the AppArmor profile status]
 
 [4] Edit the Pod yaml file and include the annotation on host to get the aaparmor profile added to pod. This is required as aaparmor is still in beta phase.
 apiVersion: v1
 kind: Pod
 metadata: 
 name: ubuntu
 annotations:
 container.apparmor.security.beta.kubernetes.io/<container-name>: localhost/<profile-name-created-by-aaparmor>
 spec: 
 containers:
 - name: ubuntu
 
 
 Replace 
 container.apparmor.security.beta.kubernetes.io/<container-name>: localhost/<profile-name-created-by-aaparmor>
 with 
 container.apparmor.security.beta.kubernetes.io/ubuntu: localhost/apparmor-deny-write
 =============================
 
 
 =============================
 Linux capabilities :
 =============================
 Process which have provilege to carry the super user task which can bypass the kernel has been categorized as capabilities.
 for e.g 
 
 CAP_CHOWN
 CAP_NET_ADMIN
 CAP_SYS_BOOT
 CAP_SYS_TIME
 etc 
 
 -- To check which process has been inherting its capabilities , run the getcap command 
 # getcap /usr/bin/ping
 /usr/bin/ping = cap_net_rw+ep
 
 -----------------
 -- How to use the capabilities in kubernetes pod:
 -----------------
 apiVersion: v1
 kind: Pod 
 metadata:
 name: nginx
 spec: 
 securityContext:
 capabilities:
 add: ["SYS_TIME"]
 drop: ["CHOWN"]
 containers:
 - command: ["sh","-c","sleep 100"]
 =============================
 
 
 =======================
 Container Sandboxing:
 =======================
 
 First understand the diff between application running on container making system call to kernel and application running on virtual machine making system call to kernel. 
 
 
 All Containers makes system calls to the same kernel beacuse they are isloated from the same VM/host. If one of the application running on container is compromised then system
 will be become vulnerable.
 
 
 ---------
 How to protect or isolate the container and OS kernel ? 
 ---------
 
 gVisor is tool from google which can be implemented which provides the isolation between container and OS kernel which intercept the system call from container and analyze the 
 system call required by the application and reroute to its firewall configured to ensure that its genuine call and provide the access to system call. 
 
 Again, gVisor will make the application slow down and take some cpu resources as its will be act as middleman between container and OS kernel.
 
 gVisor use the 2 main componenets 
 [1] Sentry : it has been designed with container in mind. 
 [2] Gofar : it is firewall proxy
 
 Each containers get its own gvisor kernel interacting between container and OS kernel. If gVisor component is broken on one container, then other gVisor on other component 
 will continue to work.
 
 ========================
 
 ==================
 kata Containers:
 ================== 
 
 Kata containers takes the diff apprach to gVisor. kata expose the container to be run in its own virtual machine which mean each container get their own dedicated kernel.
 It is indeed safer appraoch to proctect from the vulnerabilities as containers are not going to make system call to same OS kernel rather each container will get its own 
 virtual machine so they all get its own dedicated kernel. 
 
 Note : Please note not all the cloud provider allow the nested virtualization. As kata container support the nested virtualization so its difficult to get cloud providers 
 supporting it. Google Cloud provide the nested virtualization but it will be good to use the Bare Metal or dedicated hypervisor in order to make effificent 
 use of kata conatiners as performance will be affected on multi tenant cloud architecture. Google Cloud nested virtualization should be enabled manually.
 
 
 =========================
 Pod to Pod encryption in kubernetes [Istio and Linkerd]:
 =========================
 
 By default one Pod to another pod communication is unencrypted. If the one of the pod is compromized then it will become vulnerable and prone to attack.
 
 There mTLS [Mutual TLS] need to be configured to make the communication encrypted. Considering we have 1000 of pods so encryption is quite difficult. 
 
 Therefore, Istio and linkerd is best and can be implemented. Istio supports mTLS communication between pods and provide both encrypted and unencrypted communication between pods.
 
 Pod A and Pod B can have encrypted communication. howevere Pod C can communicate to Pod B via unencrypted. Istio support this architecture and hence it has been widely used. 
 
 Application between the pods communicate normally with out any encryption however, istio provide the encryption on the top of application by getting created itself as sidecar pod.
 
 
 Istio get created as sidecar pod with your main container where application run inside pod and this get applicable to other pods within the cluster. The entire cluster has 
 encryption via istion as all pods get the istio as side-car container. Although its all encrypted but if there is pod outside cluster which wants to communicate with pod which
 istio as side-car can get communicate unencrypted in plain texts and istio support that architecture. 
 
 In Istio, one pod sidecar container communicate to another pod sidecar container as encryption is done inside the side-card and communicated to another pod side-car and data 
 passed back to main container.
 
 -------------- 
 Istio support 2 modes :
 --------------
 [1] Permissive/Opportunistic [Communication within or outside the cluster]
 [2] Enforced/Strict [Communication within the cluster only]
 =========================================
 
 
 ===================================================
 Image Security and minimize the base image footprint :
 ===================================================
 [1] Always pull the images from docker hub or other repo which has got official tag. Also, ensure they are update recently. 
 [2] Ensure separate images are pulled for Application ,db , proxy server. 
 [3] Ensure images has minimal packages installed. Ensure they don't have package manager,shells,network tools,text editors,other unwanted packages. 
 -- Ensure images have only your application[writtedn in java,python etc] and its runtime dependencies only. 
 [4] Get the vulnerabilities scanning done via tool called trivy 
 for e.g.
 # trivy image httpd
 # trivy image alpine [[ minimal size image have less vulnerabilities than images of larger size]
 httpd:alpine
 ===============
 Total:0 (UNKNOWN): 0,LOW:0, MEDIUM:0,HIGH:0,CRITICAL:0)
 
 Note: Use trivy to scan the images vulnerabilities
 
 [5] Always store the data in volume or some kind of caching like redis as container are non volatile and keep crashing frequently.
 [6] Consider diff images for diff environment. For development, you can have debug tools on images but not on production environment.
 [7] USe the multi stage builds create lean production ready images.
 ========================================
 
 ==================================
 Static Analysis of user workload [or kubernetes manifest file] via kubesec tool: 
 ==================================
 kubesec can scan deployment, ds, pod,replicasets etc and provide score after analyzes for adminstrator to review 
 
 for e.g. to analyze the pod manifest before they go for authentication/autherization
 
 We can use the tool called kubesec [https://kubesec.io] 
 
 kubesec help analyze the given resource defination file and retuin scor again st the issue it found. 
 For e.g. suppose it found the pod has been critical issue running with privileged container so it provided the score and then this can be analyzed.
 
 ----------------
 Methods to install the kebesec :
 ----------------
 [1] kubesec can be installed as binary locally and run as kubesec 
 # kubesec scan pod.yaml [pod.yaml file need to be analyzed]
 
 [2] Kubesec casn be invoked online over the internet 
 # curl -sSX POST --data-binary @"pod.yaml" https://kubesec.io/scan
 
 [3] This will kubesec locally as http server 
 # kubesec https 8080 & 
 
 ==============================
 
 =====================================
 CVE Scanner for image vulnerabilities [CVE]:
 =====================================
 CVE = Common vulnerabilities and exposure 
 
 CVE maintain the record of all the known bugs and its a database which hold all sorts of bugs related to images. Its central db and eveyone submit their record of bugs. All enterprise
 can look into for the known bugs as it has unique record of all bugs that has been arise on images
 
 CVE gets the rating : 0 to 10 [10 being the highest and 0 being the lowest /safest]
 
 -- trivy is tools to scan the image for vulnerabilities.
 
 # trivy image nginx:1.18.0
 
 The above "trivy scan" return the CVE "vulnerabilities ID" [e.g. CVE-2011-3374] which can be looked into the CVE site for more details. It also provide the information about the library /module and more informationinside the TITLE section.
 
 # trivy image --severity CRITICAL nginx:1.18.0
 # trivy image --severity CRITICAL,HIGH nginx:1.18.0
 
 trivy from aquasecurity
 ==========================
 
 ================
 Best practices for Images scanning to avoid/minimze the vulnerabilities:
 ================
 [1] Continously rescan your images.
 [2] Kubernetes Admission COntroller to scan images
 [3] Have your own private repository with pre-scanned images ready to go 
 [4] integrate images with CI/CD pipelines
 =====================
 
 How to create blog in Wordpress
 Morning Theme is blogging teme in wordpress.
 Astra Theme, and then searc hfor plugin with the name ConeBlog [Another plugin - Elementor Header and Footer]
 https://www.youtube.com/watch?v=vXkaJaj6UYU [Follow the youtube vide to create blogin site free from wordpress]
 
 ==================================== 
 Monitoring Logging And Runtime Security [Falco] :
 ====================================
 Falco [company name : sysdig] -- Its tool to detect threat and analze logs. Falco does the behavioral analytics of syscall process.
 Falco is the open source standard tool for continuous risk and threat detection across Kubernetes, containers and cloud. 
 
 Way to analyze the system call and filter events that are suspcious.
 
 -- Falco interact with OS kernel via its own falco kernel which it get installed during the installation. Some Kubernetes managed service don't allow that so in this situation
 falco provide another option of installing the eBPF. Tracee tool also use the eBPF. eBPF is less intrusive than falco kernel. 
 
 systemcall are analyzed in sydig library located in USER space. Events are then filtered against the pre defined rules. and those found suspioucs alerts got redirected to output location.
 
 ----------------
 Install Falco:
 ----------------
 
 [1] Falco can be installed as unix system service via linux package.
 Or 
 [1] Falco can be installed as daemonset [ kubectl get ds , you will see the name falco] 
 
 -----------------
 -- Steps to install as linux package
 -----------------
 curl -s https://falco.org/repo/falcosecurity-3672BA8F.asc | apt-key add -
 echo "deb https://download.falco.org/packages/deb stable main" | tee -a /etc/apt/sources.list.d/falcosecurity.list
 apt-get update -y
 
 apt-get -y install linux-headers-$(uname -r)
 
 apt-get install -y falco
 
 systemctl start falco
 systemctl status falco
 
 ----------------
 Falco Configuration:
 ----------------
 To check the logs of 
 # journalctl -u falco 
 
 
 ------------------------------------
 To see the falco configuration:
 ------------------------------------
 # cat /etc/falco/falco.yaml
 
 rules_file:
 - /etc/falco/falco_rules.yaml 
 - /etc/falco/falco_rules.local.yaml 
 - /etc/falco/k8s_audit_rules.yaml 
 - /etc/falco/rules.d
 
 json_output: false [by default,its value is false. change it to true to logs the events in json format ]
 log_stderr: true
 log_syslog: true
 log_level:infor
 priority : debug [ minimum priority level is debug and its default, every event will be logged by default]
 
 file_output :
 enabled: true
 filename: /opt/falco/events.txt
 
 ---------------------------
 File which conatine all the rules :
 ---------------------------
 # cat /etc/falco/falco_rules.yaml [ This is file falco read by default to load the rules] 
 
 # /etc/falco/falco_rules.local.yaml [Use this file to make changes to any falco rules as this file will override the default file[falco_rules.yaml]. 
 
 
 -------------
 Reload the falco configuration:
 --------------
 Following changes to falco rules , reload the config. No need to restart the service as there is option to reload the config.
 
 ---------
 Hot Reload of falco configuration without restarting the falco services
 ---------
 cat /var/run/falco
 
 kill -1 $(cat /var/run/falco)
 ======================
 
 
 ============================
 Mutable va immutable infrastructure :
 ============================
 
 -- Always ensure the immutability during their runtime of container else they become vulnerable.
 
 Mutable infrastructure is infrastructure where infrastructure remain the same but the application running on the infra can be changed. for e.g. upgrade of nginx application
 from 1.18 to 1.19. 
 As there is possibility to carry out the change manually by editing the nginx.conf file and make the container malicious and hence they are mutable.
 
 Containers has by default mutable infrastructure and support rolling updates, although the base infrastructure remain the same but the application version get updated. We need to 
 ensure that infrastructure remain immutable which mean users are not allowed to write on /root fileystem inside the container as soon as they get build. If you need to carry out the 
 changes in configuration then update the application via deployment method. All we need to make sure no changes in the pod manifest file to ensure that container become immutable. 
 
 Reason for making to immutable(not writable/changeable) bcoz we don't want it become vulnerable as anyone can write to root filesystem which eventually can make changes to underlying
 host /virtual machine upon which its running.
 
 Usually we follow the pattern of changing the docker image where application version is of higher version. 
 for e.g .
 ------------
 Dockerfile:
 ------------
 From nginx 1.18 
 To 
 From ubuntu 1.19
 
 -- Once we change the nginx version in base image, we rebuild this new image with latest nginx version and create the pod which will have nginx of 1.19 version. Older pods will get 
 deleted and new pod get created as part of deployment process.
 
 While we follow the above approach but still there is possibility to carry out the change manually by editing the nginx.conf file and make the container malicious and they mutable.
 
 One of the avoid changing any files is make the root file system read-only. But if we do then pod may file as application [nginx in our case] maye be writing to some root /var location.
 
 so we should the following as best practices while creating pods, here we first discovered that nginx pod need to write to /var/cache/nginx and /var/run location.
 Here we made the root[/] filesystem readonly with the exception to write access on [/var/cache/nginx] and [/var/run] as nginx pod need to write on them else it will fail.
 so we have protected the entire root filesytem , now users cannot edit the nginx configuration we no one can edit the root filesystem.
 
 -------------
 Pod specification : {best practices, follow the below pod specification for best practices ]
 -------------
 spec:
 containers:
 - name: nginx
 image: nginx
 securityContext: 
 privileged: false [by default, its true, always change the value to "false" otherwise user get privileged to write to root filesystem on the host] 
 readOnlyRootFilesystem: true [by default its false, always change the value to "true" else root filesystem remain writable] 
 runAsUser: 1 [by default its 0, always change the value 0 else containers will run as root user, explicitly set this "runAsUser: 0"] 
 volumeMounts:
 - name: x-storage
 mountPath: /var/cache/nginx
 - name: y-storage
 mountPath: /var/run
 volumes:
 - name: x-storage
 emptyDir: {}
 - name: y-storage
 emptyDir: {}
 
 
 Always set the 3 parameters while creating pods explicitly:
 securityContext: 
 1. privileged: false [by default, its true, always change the value to "false" otherwise user get privileged to write to root filesystem on the host] 
 2. readOnlyRootFilesystem: true [by default its false, always change the value to "true" else root filesystem remain writable] 
 3. runAsUser: 1 [by default its 0, always change the value 0 else containers will run as root user, explicitly set this "runAsUser: 0"] 
 =================================
 
 
 =================== 
 Kubernetes Auditing log [ Event] :
 ===================
 
 What are events in kuberenetes ? 
 
 How to audit event in kubernetes. how do we audit and monitor what happening in our cluster.
 for e.g.
 which objects are created, who created it ,when was it created,where was request initiated from -- all these are called events in kuberenetes 
 
 By default auditing of events is provided by kube-api server but its not get enabled by default. Every request pass through the kube-api server so kube-api server 
 keep record of it in form of events. If you need auditing then enable the auditing as shon below
 
 ===================
 Events are created at 4 stages:
 ===================
 1. RequestRecieved [RR]
 2. ResponseStarted [RS]
 3. ResponseComplete [RC]
 4. Panic
 
 RR: As soon as the request goes to kub-api server to create request, this event is called RR. 
 RS: Once the request is validated, authenticated and authorized, this events is called RS. [ once the request for creating pod request is authenticated, authorized then it remin in-progress]
 RC: Once the request get completed , this event is called RC. [ for e.g pod get created sucessfully and its in running stage] 
 Panic: Incase of request error, this event is called panic.
 
 Here, if we generate the events [which are of above 4 types] for all the resource then we get hell loads of audit logs. 
 
 Therefore, it would be good to setup the rule for specific requirments to be mentioned we need the auditing for e.g. 
 
 ------------
 specific case :
 ------------
 we need to monitor the deletion of pod in specific namespace and get the events logged in to the audit logs.
 
 ----------
 audit-policy.conf [Location = /etc/kuberenetes/audit-policy.conf] we create the audit policy as per specific need
 ----------
 # Don't generate audit events for all requests in RequestReceived stage.
 
 
 # cat /etc/kuberenetes/audit-policy.conf
 
 apiVersion: audit.k8s.io/v1 # This is required.
 kind: Policy
 omitStages:
 - "RequestReceived"
 rules:
 # Log pod deletion at RequestResponse level
 - level: RequestResponse
 verb: ["delete"]
 resources:
 - group: ""
 resources: ["pods"]
 resourceNames: ["nginx_pod_name"]
 # Log "secrets in all namespace across the cluster with verb, delete,create,list,add etc " at Metadata level
 - level: Metadata
 resources:
 - group: ""
 resources: ["secrets"]
 
 
 Kubernetes 1.20 supports 2 backends services to output the audit events to file on master node and remote services to send output to falco services.
 
 The above is example of audit events to file on master node.
 
 ------------------------------------------
 --Enable the auditing of events in kubernetes:
 ------------------------------------------
 
 [1] Edit the kube-apiserver.yaml 
 - command:
 - kube-apiserver
 - --audit-log-path=/var/log/k8s-audit.log
 - --audit-policy-file=/etc/kuberenetes/audit-policy.yaml
 - --audit-log-maxage=10 [maximum no of days to keep the audit logs]
 - --audit-log-maxbackup=5 [maximum no of audit file that can retain on host]
 - --audit-log-maxsize=100 [size in megabyte before the audit file it get rotated]
 
 [2] restart the kube-api server following the above change
 
 [3] Update the pod or resource with the above information for which you enabled auditing [ for e.g . to include the volum and volume to have the reference of your audi logs]
 
 Note : highest level of verbosity where you get the max information , set the level: RequestResponse
 =================================
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
/mnt/c/Personal/github/CKS\ Exam.md
