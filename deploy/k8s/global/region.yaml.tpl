apiVersion: v1
kind: Namespace
metadata:
  name: globacl
---
apiVersion: v1
kind: Secret
metadata:
  name: globacl-signature
  namespace: globacl
type: Opaque
stringData:
  key_id: dev-ed25519
  private_key: 9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60
  public_key: d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: globacl-relay
  namespace: globacl
spec:
  replicas: 2
  selector:
    matchLabels:
      app: globacl-relay
  template:
    metadata:
      labels:
        app: globacl-relay
    spec:
      securityContext:
        runAsUser: 65532
        runAsGroup: 65532
        fsGroup: 65532
      containers:
        - name: relay
          image: ghcr.io/thevilledev/globacl:ci
          imagePullPolicy: IfNotPresent
          command: ["/usr/local/bin/globacl-relay"]
          args:
            - "__CONTROL_UPSTREAM__"
            - "0.0.0.0:7001"
            - "relay-__REGION_NAME__"
            - "__REGION_NAME__"
          env:
            - name: GLOBACL_SIGNATURE_KEY_ID
              valueFrom:
                secretKeyRef:
                  name: globacl-signature
                  key: key_id
            - name: GLOBACL_SIGNATURE_PRIVATE_KEY
              valueFrom:
                secretKeyRef:
                  name: globacl-signature
                  key: private_key
            - name: GLOBACL_RELAY_METRICS_ADDR
              value: "0.0.0.0:9101"
          ports:
            - containerPort: 7001
              name: http
            - containerPort: 9101
              name: metrics
          readinessProbe:
            httpGet:
              path: /health
              port: http
---
apiVersion: v1
kind: Service
metadata:
  name: globacl-relay
  namespace: globacl
spec:
  selector:
    app: globacl-relay
  ports:
    - name: http
      port: 7001
      targetPort: http
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: globacl-agent
  namespace: globacl
spec:
  replicas: 1
  selector:
    matchLabels:
      app: globacl-agent
  template:
    metadata:
      labels:
        app: globacl-agent
    spec:
      securityContext:
        runAsUser: 65532
        runAsGroup: 65532
        fsGroup: 65532
      containers:
        - name: agent
          image: ghcr.io/thevilledev/globacl:ci
          imagePullPolicy: IfNotPresent
          command: ["/usr/local/bin/globacl-agent"]
          args:
            - "globacl-relay.globacl.svc.cluster.local:7001"
            - "0.0.0.0:7002"
            - "/data/agent/latest.gacl"
            - "500"
            - "agent-__REGION_NAME__"
            - "60"
          env:
            - name: GLOBACL_SIGNATURE_KEY_ID
              valueFrom:
                secretKeyRef:
                  name: globacl-signature
                  key: key_id
            - name: GLOBACL_SIGNATURE_PUBLIC_KEY
              valueFrom:
                secretKeyRef:
                  name: globacl-signature
                  key: public_key
            - name: GLOBACL_AGENT_METRICS_ADDR
              value: "0.0.0.0:9102"
          ports:
            - containerPort: 7002
              name: http
            - containerPort: 9102
              name: metrics
          readinessProbe:
            httpGet:
              path: /health
              port: http
          volumeMounts:
            - name: data
              mountPath: /data
      volumes:
        - name: data
          emptyDir: {}
---
apiVersion: v1
kind: Service
metadata:
  name: globacl-agent
  namespace: globacl
spec:
  selector:
    app: globacl-agent
  ports:
    - name: http
      port: 7002
      targetPort: http
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: globacl-demo
  namespace: globacl
spec:
  replicas: 1
  selector:
    matchLabels:
      app: globacl-demo
  template:
    metadata:
      labels:
        app: globacl-demo
    spec:
      securityContext:
        runAsUser: 65532
        runAsGroup: 65532
      containers:
        - name: demo
          image: ghcr.io/thevilledev/globacl:ci
          imagePullPolicy: IfNotPresent
          command: ["/usr/local/bin/globacl-demo-app"]
          args:
            - "globacl-agent.globacl.svc.cluster.local:7002"
            - "0.0.0.0:8080"
          env:
            - name: GLOBACL_DEMO_METRICS_ADDR
              value: "0.0.0.0:9180"
          ports:
            - containerPort: 8080
              name: http
            - containerPort: 9180
              name: metrics
          readinessProbe:
            httpGet:
              path: /health
              port: http
---
apiVersion: v1
kind: Service
metadata:
  name: globacl-demo
  namespace: globacl
spec:
  selector:
    app: globacl-demo
  ports:
    - name: http
      port: 8080
      targetPort: http
