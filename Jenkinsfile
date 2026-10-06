pipeline {
  agent any
  stages {
    stage('Checkout') {
      steps {
        git branch: 'master', url: 'https://github.com/jeffrey-theog06/Phishing-Email-Analyzer.git'
      }
    }
    stage('Build Docker Image') {
      steps { bat 'docker build -t phishinganalyzer:1.0 .' }
    }
    stage('Deploy to Kubernetes') {
      steps { bat 'kubectl apply -f deployment.yaml' }
    }
    stage('Verify') {
      steps { bat 'kubectl get pods' }
    }
  }
}
