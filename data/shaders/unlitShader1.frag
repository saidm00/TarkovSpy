#version 330 core

in vec2 fragTexcoord;

uniform sampler2D inAlbedoTexture;
out vec4 outColor;

void main(void)
{
	outColor = vec4(texture(inAlbedoTexture, vec2(fragTexcoord.x, 1.0 - fragTexcoord.y)).rgb, 1.0);
}