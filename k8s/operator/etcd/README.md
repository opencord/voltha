# How to Deploy an Etcd Cluster on Kubernetes

There may be several ways to deploy an etcd cluster. The following is an example of deploying a cluster using an etcd operator; it was tested on kubernetes 1.8.5. Information about the etcd operator and how to deploy it seems to change frequently; check out the following links:
* https://coreos.com/blog/introducing-the-etcd-operator.html
* https://github.com/coreos/etcd-operator/blob/master/README.md

The procedure uses the default namespace and the default ServiceAccount. For voltha we'd likely want to use a voltha-specific namespace and ServiceAccount.

Another issue to explore is role scope. Do we create a role global to the cluster, i.e. ClusterRole, or do we create a more constrained Role.

Set up basic RBAC rules for the etcd operator:

1. Create a ClusterRole called etcd-operator.
```
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