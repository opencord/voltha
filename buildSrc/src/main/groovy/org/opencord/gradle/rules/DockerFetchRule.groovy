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
import de.gesellix.gradle.docker.tasks.DockerPullTask


/**
 * Gradle Rule class to fetch a docker image
 */
class DockerFetchRule implements Rule {

    def project

    DockerFetchRule(project) {
        this.project = project
    }

    String getDescription() {
        'Rule Usage: fetch<component-name>'
    }

    void apply(String taskName) {
        if (taskName.startsWith('fetch')) {
            project.task(taskName, type: DockerPullTask) {
                ext.compName = taskName - 'fetch'
                def spec = project.comps[ext.compName]
                imageName = spec.name + '@' + spec.digest
            }
        }
    }
}
