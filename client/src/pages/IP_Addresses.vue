<template>
  <div>
    <!--input section -->
      <v-form class="col-12" ref="form" @submit.prevent="getOutput">
        <br>
        <v-text-field
          label="Entity name"
          v-model="form.entityName"
          :rules="entityNameInputRules"
          :disabled="gettingData"
          solo
        ></v-text-field>

        <v-text-field
          label="Domain name"
          v-model="form.searchDomain"
          :rules="searchDomainInputRules"
          :disabled="gettingData"
          solo
        ></v-text-field>

        <v-text-field
          label="Keyword"
          v-model="form.keyword"
          :rules="keywordInputRules"
          :disabled="gettingData"
          solo
        ></v-text-field>

        <br>
        <div class="row">
          <div class="col text-right">
            <v-btn
              :disabled="gettingData"
              @click="resetForm"
              light
            >
              Cancel
            </v-btn>
          </div>
          <div class="col text-left">
            <v-btn
              :disabled="!formIsValid"
              :loading="gettingData"
              type="submit"
              dark
            >
              Search
            </v-btn>
          </div>
        </div>
        <br>
        <br>
      </v-form>

    <!--<br>
    <br>
    <v-card>
      <v-data-table 
        :headers='headers'
        :items='IP_records'
        :items-per-page='10'
      >
      </v-data-table>
    </v-card>-->
    <br>
    <!--change panel color in header/content tag (background;word): style="background:#23B5C3;color:white"-->
    <!--IP addresses with SSL chain records-->
    <v-card>
      <v-card-title>IP addresses with TLS/SSL certificates</v-card-title>
      <v-card-subtitle>List of all <strong>{{this.form.entityName}}</strong> IP addresses with TLS/SSL certificates<br>
                         Source(s): <strong>shodan</strong></v-card-subtitle>
      <v-card-text><strong>{{this.outS110.length-1}}</strong> record(s) found.</v-card-text>
        <v-simple-table fixed-header height="300px">
          <template v-slot:default>
            <thead>
              <tr>
                <th v-for="(key_, index) in Object.keys(outS110[0])" :key="index">
                  {{key_}}
                </th>
              </tr>
            </thead>>
            <tbody>    
              <tr v-for="(row, index) in outS110" :key="index"> 
                <td v-for="(key_, index) in Object.keys(outS110[0])" :key="index">{{row[key_]}}</td>
              </tr>
            </tbody>
          </template>
        </v-simple-table>
    </v-card>
    <br>
    <!--IP addresses using SSH/FTP/RDP protocols-->
    <v-card>
      <v-card-title>IP addresses using SSH/FTP/RDP protocols</v-card-title>
      <v-card-subtitle>List of all {{this.form.entityName}} IP addresses using SSH/FTP/RDP protocols<br>
                         Source(s): <strong>shodan, ipinfo</strong></v-card-subtitle>
      <v-card-text><strong>{{this.outS14.length-1}}</strong> record(s) found.</v-card-text>
      <v-simple-table fixed-header height="300px">
        <template v-slot:default>
          <thead>
            <tr>
              <th v-for="(key_, index) in Object.keys(outS14[0])" :key="index">
                {{key_}}
              </th>
            </tr>
          </thead>>
          <tbody>    
            <tr v-for="(row, index) in outS14" :key="index"> 
              <td v-for="(key_, index) in Object.keys(outS14[0])" :key="index">{{row[key_]}}</td>
            </tr>
          </tbody>
        </template>
      </v-simple-table>
    </v-card>
  </div>
</template>

<script>
import getOutput from "@/services/getOutput";
export default {
  data() {
    const defaultForm = Object.freeze({
      entityName: "",
      searchDomain: "",
      keyword: "",
    })

    const defaultTable = [
        {"-": '-', "-":'-', "-":'-', "-":'-'}
    ]

    return {
      /*headers:[
        {
            text: 'IP address',
            align: 'start',
            sortable: false,
            value: 'Host',
        },
        { text: 'Protocol', value: 'Protocol' },
        { text: 'Organization', value: 'Organization' },
        { text: 'SSL certificate issuer', value: 'SSLCertIssuerCommonName' },
        { text: 'Website title', value: 'WebsiteTitle' },
        { text: 'SSL certificate signature algorithm', value: 'SSLCertSignatureAlgorithm' },
        { text: 'CVE No.', value: 'NoCVE' },
        { text: 'Highest CVSS score', value: 'Highest CVSS' },
        { text: 'Corresponding CVE', value: 'CorrespondingCVE' },
      ],
      IP_records:[],*/
      form: Object.assign({}, defaultForm),
      entityNameInputRules: [
        value => !!value || 'This field is required',
        value => this.checkEntityNameValidity() || 'Entity name should not contain /\\\. "$*<>:|?'
      ],
      searchDomainInputRules: [
        value => !!value || 'This field is required',
        value => this.checkSearchDomainValidity() || 'Please skip http://www. or https://www. in your domain name',
        value => value.includes(".") || 'This is not a valid domain name'
      ],
      keywordInputRules: [
        value => !!value || 'This field is required',
      ],
      defaultForm,
      gettingData: false,
      panelDisabled: true,
      outS110: [{"-": '-', "-":'-', "-":'-', "-":'-','-':'-',
                 "-": '-', "-":'-', "-":'-', "-":'-','-':'-'}],
      outS14: [{"-": '-', "-":'-', "-":'-', "-":'-','-':'-',
                 "-": '-', "-":'-', "-":'-', "-":'-','-':'-'}],
      mongoDB: { password: "jonathan", database: "ClientData" }, //<------is this useful?
    };
  },
  methods: {
    resetForm() {
      this.form = Object.assign({}, this.defaultForm)
      this.$refs.form.reset()
    },
    notifyFinish() {
      this.$notify({
        message: "Completed!",
        icon: "ti-check",
        horizontalAlign: 'center',
        verticalAlign: 'top',
        type: "success",
        timeout: 60000
      })
    },
    async getOutput() {
      this.gettingData = true;
      this.panelDisabled = true;
      const response = await getOutput.getOutput({
        entityName: this.form.entityName,
        searchDomain: this.form.searchDomain,
        keyword: this.form.keyword
      });
      this.outS110 = response.data["outS110"];
      this.cleanOutS110()
      this.outS14 = response.data["outS14"];
      this.cleanOutS14()
      this.panelDisabled = false;
      this.gettingData = false;
      this.notifyFinish()
    },
    cleanOutS110(){
      this.outS110=this.outS110.map((e)=>{
        return{
          "IP Address": e.Host,
          Protocol:e.Protocol,
          Organization: e.Organization,
          "SSL certificate issuer":e.SSLCertIssuerCommonName,
          "Website Title":e.WebsiteTitle,
          "SSL certificate signature algorithm": e.SSLCertSignatureAlgorithm,
          "CVE No.": e.NoCVE,
          "Highest CVSS Score": e.HighestCVSS,
          "Corresponding CVE": e.CorrespondingCVE
        }
      })
    },
    cleanOutS14(){
      this.outS14=this.outS14.map((e)=>{
        return{
          "IP Address": e.Host,
          "Host name": e.HostName,
          Port:e.Port,
          Protocol:e.Protocol,
          Service: e.Service,
          "Common platform enumeration CPE":e.ComonPlatformEnumerationCPE,
          "Vulnerability details":e.VulnerabilityDetails,
          "CVE No.": e.NoCVE,
          "Highest CVSS Score": e.HighestCVSS,
          "Corresponding CVE": e.CorrespondingCVE
        }
      })
    },
    checkEntityNameValidity(){
      return !(this.form.entityName.includes("/") || this.form.entityName.includes("\\")||
      this.form.entityName.includes(".") || this.form.entityName.includes("\"")||
      this.form.entityName.includes("$") || this.form.entityName.includes("*")||
      this.form.entityName.includes("<") || this.form.entityName.includes(">")||
      this.form.entityName.includes(":") || this.form.entityName.includes("|")||
      this.form.entityName.includes("?"))
    },
    checkSearchDomainValidity(){
      return !(this.form.searchDomain.includes("http://") || this.form.searchDomain.includes("https://")
        || this.form.searchDomain.includes("www."))
    },
  },
  computed: {
    formIsValid () {
      var noErrEntityName = this.form.entityName
      var noErrSearchDomain = this.form.searchDomain
      var noErrKeyword = this.form.keyword
      if (noErrEntityName){
        noErrEntityName = this.checkEntityNameValidity()
      }
      if (noErrSearchDomain){
        noErrSearchDomain = this.checkSearchDomainValidity() || !this.form.searchDomain.includes(".")
      }
      if (noErrKeyword){
        noErrKeyword = true
      }
      return (
        noErrEntityName &&
        noErrSearchDomain &&
        noErrKeyword
      )
    },
  },
  /*async created () {
    const IP_records = await getOutput.getOutput()
    const promises = IP_records.map(async (e) => {
      return{
        "IP Address": e.Host,
        Protocol:e.Protocol,
        Organization: e.Organization,
        "SSL certificate issuer":e.SSLCertIssuerCommonName,
        "Website Title":e.WebsiteTitle,
        "SSL certificate signature algorithm": e.SSLCertSignatureAlgorithm,
        "CVE No.": e.NoCVE,
        "Highest CVSS Score": e.HighestCVSS,
        "Corresponding CVE": e.CorrespondingCVE
      }
    })

    await Promise.all(promises)

    this.IP_records = IP_records
  }*/
};
</script>
<style>
.v-card__title {
  color: rgb(62, 169, 120)!important;
}
</style>
