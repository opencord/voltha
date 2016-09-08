/*
 * Copyright 2012 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.opencord.gradle.rules

import org.gradle.api.Rule
import de.gesellix.gradle.docker.tasks.DockerPushTask


/**
 * Gradle Rule class to publish (push) a docker image to a private repo
 */
class DockerPublishRule implements Rule {

    def project
    def dependency

    DockerPublishRule(project) {
        this.project = project
    }

    DockerPublishRule(project, dependency) {
        this.project = project
        this.dependency = dependency
    }

    String getDescription() {
        'Rule Usage: publish<component-name>'
    }

    void apply(String taskName) {
        if (taskName.startsWith('publish')) {
            project.task(taskName, type: DockerPushTask) {
                ext.compName = taskName - 'publish'
                println "Publish rule: $taskName + $compName"
                def tagTask = "tag$compName"
                println "Tagtask: $tagTask"
                if (dependency) {
                    dependsOn dependency
                }
                dependsOn tagTask
                def spec = project.comps[ext.compName]
                repositoryName = spec.name + ':' + project.targetTag
                registry = project.targetReg
            }
        }
    }
}
