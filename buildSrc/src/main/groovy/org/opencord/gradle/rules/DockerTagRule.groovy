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
import de.gesellix.gradle.docker.tasks.DockerTagTask


/**
 * Gradle Rule class to tag a docker image
 */
class DockerTagRule implements Rule {

    def project

    DockerTagRule(project) {
        this.project = project
    }

    String getDescription() {
        'Rule Usage: tag<component-name>'
    }

    void apply(String taskName) {
        if (taskName.startsWith('tag') && !taskName.equals('tag')) {
            project.task(taskName, type: DockerTagTask) {
                ext.compName = taskName - 'tag'
                def spec = project.comps[compName]
                imageId = spec.name + '@' + spec.digest
                tag = compName + ':' + project.targetTag
            }
        }
    }
}
