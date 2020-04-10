#version 330 core

layout(location = 0) in vec3 inPosition;
layout(location = 1) in vec2 inTexcoord; 

uniform mat3 inWorldToScreen;

out vec2 fragTexcoord;

void main(void)
{
	fragTexcoord = inTexcoord;

	gl_Position = vec4(vec2(inWorldToScreen * vec3(inPosition.xy, 1.0)), -0.5, 1.0);
}