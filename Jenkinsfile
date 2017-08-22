node('build') {
    stage 'Checkout cord repo'
    checkout([$class: 'RepoScm', currentBranch: true, manifestRepositoryUrl: 'https://gerrit.opencord.org/manifest', quiet: true])

    dir ('incubator/voltha') {
        try {
            stage 'Bring up voltha dev vm'
            sh 'vagrant up voltha'

            stage 'Remove the pre-created venv-linux'
            sh 'vagrant ssh -c "rm -rf /cord/incubator/voltha/venv-linux"'

            stage 'Use the jenkins voltha.yml file'
            sh 'vagrant ssh -c "cp /cord/incubator/voltha/voltha/voltha.jenkins.yml /cord/incubator/voltha/voltha/voltha.yml"'

            stage 'Build voltha'
            sh 'vagrant ssh -c "cd /cord/incubator/voltha && source env.sh && make fetch-jenkins && make jenkins" voltha'

            stage 'Bring up voltha containers'
            sh 'vagrant ssh -c "cd /cord/incubator/voltha && source env.sh && docker-compose -f compose/docker-compose-docutests.yml up -d" voltha'

            stage 'Run Integration Tests'
            sh 'vagrant ssh -c "cd /cord/incubator/voltha && source env.sh && make jenkins-test" voltha'

            currentBuild.result = 'SUCCESS'
            slackSend channel: '#voltha', color: 'good', message: "${env.JOB_NAME} (${env.BUILD_NUMBER}) Build success.\n${env.BUILD_URL}"
        } catch (err) {
            currentBuild.result = 'FAILURE'
            slackSend channel: '#voltha', color: 'danger', message: ":dizzy_face: Build failed ${env.JOB_NAME} (${env.BUILD_NUMBER})\n${env.BUILD_URL}"
        } finally {
            sh 'vagrant destroy -f voltha'
        }
        echo "RESULT: ${currentBuild.result}"
    }
}
