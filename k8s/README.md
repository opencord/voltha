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
