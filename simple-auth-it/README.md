# simple-auth-it

Simple authentication integration tests.

## run all test in class

```
mvn -Dtest={test class} docker:start test docker:stop
```

example:

```
mvn -Dtest=SimpleAuthBackendIT docker:start test docker:stop
```

## run one test in class

```
mvn -Dtest={test class}#{test method} docker:start test docker:stop
```

example:

```
mvn -Dtest=SimpleAuthBackendIT#health docker:start test docker:stop
```

## kill all containers

```
docker kill $(docker ps -q)
```

## remove all containers

```
docker rm $(docker ps -a -q)
```
