node {
  def suffix = ""
  def imageBaseName="qube-git-listener"
  def imgName = "qubeship/${imageBaseName}${suffix}"
  def dockerFileName = "Dockerfile-wsgi${suffix}"


  println (imgName + ":" + dockerFileName)
  checkout poll:false,scm: [
          $class: 'GitSCM',
          branches: [[name: "${commithash}"]],
          userRemoteConfigs: [[
            url: "${git_repo}",
            credentialsId: 'github',
            refspec: '+refs/heads/*:refs/remotes/origin/* +refs/pull/*:refs/remotes/origin/pr/*'
          ]]
      ]
  def branch=(branch?:"master").tokenize('/').last()
  gitCommit = sh(returnStdout: true, script: 'git rev-parse HEAD', label:"Get Commit id")
  shorthash = gitCommit.take(6)
  def imageVersion="${branch}.${shorthash}.${env.BUILD_NUMBER}"


  def image = docker.build ("$imgName:${imageVersion}", "-f $dockerFileName .")
  image.tag("latest")

  docker.withRegistry('https://gcr.io/', 'gcr:qubeship') {
       image.push()
       image.push("latest")
  }  
  withCredentials([[$class: 'StringBinding',credentialsId:
    'qubeship-prod-k8s2', variable: 'TOKEN']]) {
        sh '''
        set +x +e
        sed -ibak "s/%image%/$imgName:${imageVersion}/g" .qube/production/qube-resources.yaml
        cat .qube/production/qube-resources.yaml
        kubectl apply -f .qube/services/qube-services.yaml --record --token $TOKEN --namespace platform --server=https://104.198.6.255  --insecure-skip-tls-verify=true
        kubectl apply -f .qube/production/qube-resources.yaml --record --token $TOKEN --namespace platform --server=https://104.198.6.255  --insecure-skip-tls-verify=true
        '''
   }


}
