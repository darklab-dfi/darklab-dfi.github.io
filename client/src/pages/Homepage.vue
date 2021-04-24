<template>
    <div>
        
        <h2>Welcome to DarkLab DFI Tracker</h2>
        <h4>Monitor the vulnerabilities of your digital assets, anywhere, anytime.</h4>
        <h5>Choose the area you would like to track:</h5>
        <br>
        <v-container fluid>
            <v-row dense>
                <v-col>
                    <v-card>
                        <v-img
                        src="https://external-content.duckduckgo.com/iu/?u=https%3A%2F%2Fimages.techhive.com%2Fimages%2Farticle%2F2016%2F05%2Fdomain_names_tld-100663180-primary.idge.jpg&f=1&nofb=1"
                        class="white--text align-end"
                        gradient="to bottom, rgba(0,0,0,.1), rgba(0,0,0,.5)"
                        height="200px"
                        >
                        <v-card-title>Domains and Subdomains</v-card-title>
                        </v-img>

                        <v-card-actions>
                            <v-btn icon to='/domains_subdomains'>
                                <v-icon>mdi-arrow-right</v-icon>
                            </v-btn>
                        </v-card-actions>
                    </v-card>
                    <br>
                    <v-card>
                        <v-img
                        src="https://external-content.duckduckgo.com/iu/?u=https%3A%2F%2Fwww.chino.io%2Fblog%2Fcontent%2Fimages%2F2017%2F02%2FIP-Adress.jpg&f=1&nofb=1"
                        class="white--text align-end"
                        gradient="to bottom, rgba(0,0,0,.1), rgba(0,0,0,.5)"
                        height="200px"
                        >
                        <v-card-title>IP Addresses</v-card-title>
                        </v-img>

                        <v-card-actions>
                            <v-btn icon to='/ip_addresses'>
                                <v-icon>mdi-arrow-right</v-icon>
                            </v-btn>
                        </v-card-actions>
                    </v-card>
                    <br>
                     <v-card>
                        <v-img
                        src="https://external-content.duckduckgo.com/iu/?u=https%3A%2F%2Ftse3.mm.bing.net%2Fth%3Fid%3DOIP.b7qEtAVQNWwopieYZq7HywHaD8%26pid%3DApi&f=1"
                        class="white--text align-end"
                        gradient="to bottom, rgba(0,0,0,.1), rgba(0,0,0,.5)"
                        height="200px"
                        >
                        <v-card-title>Email Addresses</v-card-title>
                        </v-img>
                        
                        <v-card-actions>
                            <v-btn icon to='/email_addresses'>
                                <v-icon>mdi-arrow-right</v-icon>
                            </v-btn>
                        </v-card-actions>
                    </v-card>
                    <br>
                    <v-card>
                        <v-img
                        src="https://external-content.duckduckgo.com/iu/?u=https%3A%2F%2Ftse2.mm.bing.net%2Fth%3Fid%3DOIP.YxF68cqT9ikCoAWLyL1SFgHaFL%26pid%3DApi&f=1"
                        class="white--text align-end"
                        gradient="to bottom, rgba(0,0,0,.1), rgba(0,0,0,.5)"
                        height="200px"
                        >
                        <v-card-title>Cloud Buckets</v-card-title>
                        </v-img>

                        <v-card-actions>
                            <v-btn icon to='/cloud_buckets'>
                                <v-icon>mdi-arrow-right</v-icon>
                            </v-btn>
                        </v-card-actions>
                    </v-card>
                </v-col>
            </v-row>
        </v-container>
    </div>
</template>