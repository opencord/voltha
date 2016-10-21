node ('build') {
    stage 'Checkout cord repo'
    m_url = 'https://gerrit.opencord.org/manifest'
    checkout changelog: false, poll: false, scm [$class: 'RepoScm', currentBranch: true, manifestRepositoryUrl: m_url, quiet: true]

    dir ('incubator/voltha') {
        try {
            stage 'Bring up voltha dev vm'
            sh 'vagrant up voltha'

            stage 'Build voltha'
            sh 'vagrant ssh -c "cd /voltha && source env.sh && make fetch && make" voltha'

            stage 'Bring up voltha containers'
            sh 'vagrant ssh -c "cd /voltha && source env.sh && docker-compose -f compose/docker-compose-system-test.yml up -d" voltha'

            currentBuild.result = 'SUCCESS'
            step([$class: 'Mailer', recipients: 'cord-dev@opencord.org', sendToIndividuals: false])
        } catch (err) {
            currentBuild.result = 'FAILURE'
            step([$class: 'Mailer', notifyEveryUnstableBuild: true, recipients: 'cord-dev@opencord.org', sendToIndividuals: false])
        } finally {
            sh 'vagrant destroy -f voltha'
        }
        echo "RESULT: ${currentBuild.result}"
    }
}
