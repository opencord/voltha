# How to set up networking

## Basic requirement

When Kubernetes is first deployed, you are required to setup networking by installing Weave.  
This ensures the proper deployment of containers such as kube-dns.

The most common network plugin used is Weave which can be deployed by issuing the following command:

```
kubectl apply -f "https://cloud.weave.works/k8s/net?k8s-version=$(kubectl version | base64 | tr -d '\n')"
```
## Support for multiple network interfaces 

When a container is deployed in Kubernetes, a single network interface is assigned to the container.

Some containers may require multiple interfaces, thus the CNI Genie package can provide that 
capability.

It can be installed by issuing the command:

```
kubectl apply -f https://raw.githubusercontent.com/Huawei-PaaS/CNI-Genie/master/conf/1.8/genie.yaml
```

Once CNI Genie is installed, you will need to modify your k8s templates to include the necessary
annotations statement.  This statement allows you specify 1 or more network plugin types.

e.g.
```
  ...
  template:
    metadata:
      labels:
        app: your-app-name
      annotations:
        cni: "weave"
    spec:
    ...

```

If you wish to only use weave for your container, you would modify the template as described above.

If you wish to include 2 or more interfaces, you can do so by changing the "cni" string with a 
list of comma-separated network plugins.  

e.g.

``` /etc/cni/net.d/10-mybridge.conf
  ...
  template:
    metadata:
      labels:
        app: your-app-name
      annotations:
        cni: "weave,mybridge,myvlan"
    spec:
    ...
```

Here "myvlan" and "mybridge" refer to cni templates that you would have previously defined on 
each host of your cluster.  

e.g.

```
/etc/cni/net.d/10-mybridge.conf

{
    "name": "mybridge",
    "type": "bridge",
    "bridge": "mybridge",
    "isGateway": true,
    "ipMask": true,
    "ipam": {
      "type": "host-local",
      "subnet": "10.11.12.0/24",
      "routes": [
        { "dst": "0.0.0.0/0" }
      ]
    }
}
```

Refer to the Kubernetes documentation for more information on the supported network plugins and 
how to configure them.

# How to set up Ingress into Services deployed on a Kubernetes Cluster

1. Create an ingress controller and then an Ingress resource:
```
cd incubator/voltha/k8s
kubectl apply -f ingress/
```
2. Add hostnames k8s-consul and k8s-grafana to the DNS (or edit /etc/hosts). Set the IP address of each of these hosts to that of the kubernetes master node. 

3. In your favorite browser, enter the following URLs:
* http://k8s-consul:30080 for Consul UI access
* http://k8s-grafana:30080 for Grafana UI access

The current solution uses the hostname carried in the HTTP header to map the ingress to the appropriate service.
That's the reason for the DNS configuration. There is another solution that would do away with this DNS requirement; that solution uses URL paths to perform the service mapping. More investigation is required to
look into this approach.

The ingress port number is dynamically assigned by Kubernetes from the default NodePort range 30000-32767, which is apparently configurable. The ingress service spec anchors the HTTP port to 30080 and the HTTPS port to 30443.

# How to Deploy an Etcd Cluster on Kubernetes

There may be several ways to deploy an etcd cluster. The following is an example of deploying a cluster using an etcd operator; it was tested on kubernetes 1.8.5. Information about the etcd operator and how to deploy it seems to change frequently; check out the following links:
* https://coreos.com/blog/introducing-the-etcd-operator.html
* https://github.com/coreos/etcd-operator/blob/master/README.md

The procedure uses the default namespace and the default ServiceAccount. For voltha we'd likely want to use a voltha-specific namespace and ServiceAccount.

Another issue to explore is role scope. Do we create a role global to the cluster, i.e. ClusterRole, or do we create a more constrained Role.

Set up basic RBAC rules for the etcd operator:

1. Create a ClusterRole called etcd-operator.
```
cd incubator/voltha/k8s/operator/etcd
kubectl create -f cluster_role.yml
kubectl get clusterrole
```
2. Create a ClusterRoleBinding that binds the default service account in the default namespace to the new role.
```
kubectl create -f cluster_role_binding.yml
kubectl get clusterrolebinding
```
Deploy the etcd operator.
```
kubectl create -f operator.yml
```
The etcd operator will automatically create a CustomResourceDefinition (CRD).
```
$ kubectl get customresourcedefinitions
NAME                                    AGE
etcdclusters.etcd.database.coreos.com   4m
```
Deploy the etcd cluster.
```
kubectl create -f etcd_cluster.yml
```
