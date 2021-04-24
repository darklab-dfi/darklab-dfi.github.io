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
      </v-form>

    <br>
    <br>
    <h3>Domains</h3>
    <!--Domains with similar names-->
    <v-card>
      <div class="domain_similar_name">
        <v-card-title>Domain squatting</v-card-title>
        <v-card-subtitle>List of all domains with names similar to <strong>{{form.searchDomain}}</strong><br>
                         Source(s): <strong>Immuniweb</strong></v-card-subtitle>
        <v-card-text><strong>{{countSimilarDomain}}</strong> domain(s) found. </v-card-text>
        <div class="scroll">
            <v-simple-table fixed-header height="300px">
                <template v-slot:default id="outS19" class='text_left'>
                    <thead>
                        <tr>
                        <th v-for="(key_, index) in Object.keys(outS19[0])" :key="index">{{key_}}</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr v-for="(row, index) in outS19" :key="index">
                        <td v-for="(key_, index) in Object.keys(outS19[0])" :key="index">{{row[key_]}}</td>
                        </tr>
                    </tbody>
                </template>
            </v-simple-table>
        </div>
      </div>
    </v-card>

    <br>
    <h3>Subdomains</h3>
    <!--change panel color in header/content tag (background;word): style="background:#23B5C3;color:white"-->
    <!--non-production entry points-->
     <v-card>
      <v-card-title><strong>{{form.searchDomain}}</strong> Non-production entry points</v-card-title>
      <v-card-subtitle>Source(s): <strong> securitytrails, dns, ipinfo, whatsmydns.net</strong></v-card-subtitle>
        <!--distribution of subdomains pie chart-->
        <GChart
          type="PieChart"
          :data="outS12.data"
          :options="outS12.options"
        />
    </v-card>
    <br>
    <v-card>
      <v-card-title>Login Portals </v-card-title>
      <v-card-subtitle>List of all <strong>{{form.searchDomain}}</strong> subdomains containing login portals<br>
                        Source(s): <strong>node-fetch, securitytrails, dns, ipinfo, whatsmydns.net</strong></v-card-subtitle>
      <v-card-text><strong>{{this.outS15.length-1}}</strong> subdomain(s) found.</v-card-text>
      <v-simple-table fixed-header height="300px">
        <template v-slot:default>
          <thead>
            <tr>
              <th v-for="(key_, index) in Object.keys(outS15[0])" :key="index">
                {{key_}}
              </th>
            </tr>
          </thead>>
          <tbody>    
            <tr v-for="(row, index) in outS15" :key="index"> 
              <td v-for="(key_, index) in Object.keys(outS15[0])" :key="index">{{row[key_]}}</td>
            </tr>
          </tbody>
        </template>
      </v-simple-table>
    </v-card>
    <br>
    <v-card>
      <v-card-title>Subdomains on SURBL/Spamhaus blocking list</v-card-title>
       <v-card-subtitle>List of all <strong>{{form.searchDomain}}</strong> subdomains containing login portals<br>
                        Source(s): <strong>feodotracker, urlhaus, securitytrails, dns, ipinfo, whatsmydns.net</strong></v-card-subtitle>
      <v-card-text><strong>{{this.outS16.length-1}}</strong> subdomain(s) found.</v-card-text>
      <v-simple-table fixed-header height="300px">
        <template v-slot:default>
          <thead>
            <tr>
              <th v-for="(key_, index) in Object.keys(outS16[0])" :key="index">
                {{key_}}
              </th>
            </tr>
          </thead>>
          <tbody>    
            <tr v-for="(row, index) in outS16" :key="index"> 
              <td v-for="(key_, index) in Object.keys(outS16[0])" :key="index">{{row[key_]}}</td>
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
      outS12: {
        data: [
          ['Entry point','No. of subdomains']
        ],
        options: {title:"Distribution of subdomains by entry point type",theme: 'material',height:350}
      },
      outS15: [{"-": '-', "-":'-', "-":'-', "-":'-','-':'-'}],
      outS16: [{"-": '-', "-":'-', "-":'-', "-":'-',
                        '-': '-', "-":'-', "-":'-', '-':'-'}] ,
      outS19: [{'-':'-','-':'-'}],
      /*outS31_fileCount_byType:{
        data: [
          ["Types","Number of files"]
        ],
        //options: {chart:{title:"File Count by Bucket Type"},legend: { position: "none" }} <---material chart
        options: {title:"File count by bucket type",legend: { position: "none" },theme: 'material',height:350}
      },*/
      countSimilarDomain: 0,
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
      this.outS12 = response.data["outS12"];
      this.cleanOutS12()
      this.outS15 = response.data["outS15"];
      this.cleanOutS15()
      this.outS16 = response.data["outS16"];
      this.cleanOutS16()
      this.outS19 = response.data["outS19"];
      this.cleanOutS19()
      this.panelDisabled = false;
      this.gettingData = false;
      this.notifyFinish()
    },
    cleanOutS12(){
      //distribution of subdomains pie chart
      var c = 0;
      var d = 0;
      var e = 0;
      var f = 0;
      var g = 0;
      var h = 0;
      var j = 0;
      for (var i = 0; i < this.outS12.length; i++) {
        var dev_pos = this.outS12[i]["Domain"].toString().indexOf('dev');
        var uat_pos = this.outS12[i]["Domain"].toString().indexOf('uat');
        var qa_pos = this.outS12[i]["Domain"].toString().indexOf('qa');
        var test_pos = this.outS12[i]["Domain"].toString().indexOf('test');
        var stag_pos = this.outS12[i]["Domain"].toString().indexOf('stag');
        var temp_pos = this.outS12[i]["Domain"].toString().indexOf('temp');
        var tmp_pos = this.outS12[i]["Domain"].toString().indexOf('tmp');
        if (dev_pos>-1){
          c++;
        }else if(uat_pos>-1){
          d++;
        }else if(qa_pos>-1){
          e++;
        }else if(test_pos>-1){
          f++;
        }else if(stag_pos>-1){
          g++;
        }else if(temp_pos>-1){
          h++;
        }else if(tmp_pos>-1){
          j++;
        };
        this.outS12["data"]=[
          ['Entry point','No. of subdomains'],
          ['dev',c],
          ['uat',d],
          ['qa',e],
          ['test',f],
          ['stag',g],
          ['temp',h],
          ['tmp',j]
        ];
     };
    },
    cleanOutS15() {
      this.outS15 = this.outS15.map((e) => {
        return {
          Domain:e.Domain,
          IP:e.IP,
          ISP:e.ISP,
          "Host name":e.hostname,
        }
      });
    },
    cleanOutS16(){
        this.outS16 = this.outS16.map((e)=>{
            return{
                Domain: e.Domain,
                IP:e.IP,
                Botnet:e.Botnet,
                "Botnet Details":e.Botnet_Details,
                "Malicious URL":e.MaliciousURL,
                "SURBL Blacklist":e.Malicious_SURBL_Blacklist,
                "Spamhaus Blacklist":e.Malicious_Spamhaus_Blacklist,
                "Other Details":e.Details,
            }
        })
    },
    cleanOutS19() {
      this.outS19 = this.outS19.map((e) => {
        return {
          "Domain Name": e.Domain,
          "Server IP address": e.ServerIP,
        }
      });
      //count similar domains
      this.countSimilarDomain=this.outS19.length;
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
    /*cleanOutS16(){
      for(var i=0; i<this.outS16.length; i++){
        if(!this.outS16[i].Botnet.includes('false') || !this.outS16[i].Botnet.includes(' ') || !this.outS16[i].MaliciousURL.includes('ok') || 
           !this.outS16[i].MaliciousURL.includes('N/A') || !this.outS16[i].MaliciousURL.includes(' ')){
            this.outS16_cleaned['data'].push([this.outS16[i]['Domain'],this.outS16[i]['IP'],this.outS16[i]['Botnet'],this.outS16[i]['Botnet_Details'],
                                              this.outS16[i]['MaliciousURL'],this.outS16[i]['Malicious_SURB_Blacklist'],
                                              this.outS16[i]['Malicious_Spamhaus_Blacklist'],this.outS16[i]['Details']])
          }
      }
    }*/
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
};
</script>
<style lang='scss'>
.v-card__title {
  color: rgb(62, 169, 120)!important;
}
</style>
