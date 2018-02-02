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
