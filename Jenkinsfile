node('build') {
    stage 'Checkout cord repo'
    checkout([$class: 'RepoScm', currentBranch: true, manifestRepositoryUrl: 'https://gerrit.opencord.org/manifest', quiet: true])

    dir ('incubator/voltha') {
        try {
            stage 'Bring up voltha dev vm'
            sh 'vagrant up voltha'

            stage 'Build voltha'
            sh 'vagrant ssh -c "cd /voltha && source env.sh && make fetch && make" voltha'

            stage 'Bring up voltha containers'
            sh 'vagrant ssh -c "cd /voltha && source env.sh && docker-compose -f compose/docker-compose-system-test.yml up -d" voltha'

            stage 'Run Integration Tests'
            sh 'vagrant ssh -c "cd /voltha && source env.sh && make smoke-test" voltha'

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
