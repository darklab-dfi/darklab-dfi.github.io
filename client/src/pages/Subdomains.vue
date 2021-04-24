<template>
  <div>
    <!--input section -->
      <v-form class="col-12" ref="form" @submit.prevent="getOutput">
        <br>
        <v-text-field
          label="Entity Name"
          v-model="form.entityName"
          :rules="inputRules"
          :disabled="gettingData"
          solo
        ></v-text-field>

        <v-text-field
          label="Search domain"
          v-model="form.searchDomain"
          :rules="inputRules"
          :disabled="gettingData"
          solo
        ></v-text-field>

        <v-text-field
          label="Keyword"
          v-model="form.keyword"
          :rules="inputRules"
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

    <br>
    <br>

    <!--change panel color in header/content tag (background;word): style="background:#23B5C3;color:white"-->
    <!--non-production entry points-->
     <v-card>
      <div class="non-prod_entry_points">
        <v-card-title>Non-production entry points</v-card-title>
        <v-card-text>
          <div class="row">
            <div class="col">
              <GChart
                type="PieChart"
                :data="outS12.data"
                :options="outS12.options"
              />
            </div>
              <!--Mateiral design available only for bar chart-->
              <!--
              <GChart
                :settings="{packages: ['bar']}"    
                :data="outS31_fileCount_byType.data"
                :options="outS31_fileCount_byType.options"
                :createChart="(el, google) => new google.charts.Bar(el)"
              />
              -->
          </div>
        </v-card-text>
      </div>
    </v-card>
    <br>
    <br>
    <v-card>
      <div class="">
        <v-card-title>Login Portals</v-card-title>
        <v-card-text>
          <div class="scroll">
            <table id="outS15" class='text_left'>
            <thead>
              <tr>
                <th v-for="(key_, index) in Object.keys(outS15[0])" :key="index">{{key_}}</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="(row, index) in outS15" :key="index">
                <td v-for="(key_, index) in Object.keys(outS15[0])" :key="index">{{row[key_]}}</td>
              </tr>
            </tbody>
            </table>
          </div>
        </v-card-text>>
      </div>
    </v-card>
          <!--DMARC record
          <v-expansion-panel>
            <v-expansion-panel-header>DMARC record</v-expansion-panel-header>
            <v-expansion-panel-content>
              <div class="scroll">
                <table id="outS18" class='text_left'>
                <thead>
                  <tr>
                    <th class="text-left">Description</th>
                    <th class="text-left">Value</th>
                  </tr>
                </thead>
                <tbody>
                  <tr v-for="item in outS18" :key="item.description">
                    <td>{{ item.description }}</td>
                    <td>{{ item.value }}</td>
                  </tr>
                </tbody>
                </table>
              </div>
            </v-expansion-panel-content>
          </v-expansion-panel>-->
    <br>
    <br>
  </div>
</template>

<script>
import getOutput from "@/services/getOutput";
//import * as d3 from "d3";
export default {
  data() {
    //var { c, d, e, f, g, h, j }=init();
    const defaultForm = Object.freeze({
      entityName: "",
      searchDomain: "",
      keyword: "",
    })

    const defaultTable = [
        {"col 1": '-', "col 2":'-', "col 3":'-', "col 4":'-'}
    ]

    return {
      form: Object.assign({}, defaultForm),
      inputRules: [
        value => !!value || 'This field is required',
      ],
      defaultForm,
      gettingData: false,
      panelDisabled: true,
      outS12: {
        data: [
          //[['dev','uat','qa','test','stag','temp','tmp'],[c,d,e,f,g,h,j]]
        ],
        options: {title:"Distribution of subdomains by entry point type",theme: 'material',height:350}
      },
      outS15: [{"col 1": '-', "col 2":'-', "col 3":'-', "col 4":'-','col 5':'-','col 6':'-'}],
      outS16: defaultTable,      
      outS31_fileCount_byType:{
        data: [
          ["Types","Number of files"]
        ],
        //options: {chart:{title:"File Count by Bucket Type"},legend: { position: "none" }} <---material chart
        options: {title:"File count by bucket type",legend: { position: "none" },theme: 'material',height:350}
      },
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
      this.panelDisabled = false;
      this.gettingData = false;
      this.notifyFinish()
    },
    cleanOutS15() {
      this.outS15 = this.outS15.map((e) => {
        return {
          Domain:e.Domain,
          IP:e.IP,
          ISP:e.ISP,
          RecordType:e.RecordType,
          hostname:e.hostname,
          LoginPortal:e.LoginPortal
        }
      });
    },
    cleanOutS12(){
      //cleaning data
      this.outS12 = this.outS12.map((e) => {
        return {
         Domain: e.Domain,
         IP: e.IP,
         ISP: e.ISP,
         hostname: e.hostname
        }
      });
    
      //distribution of subdomains pie chart
      /*for (var i = 0; i < this.outS12.length; i++) {
        var dev_pos = this.outS12[i][Domain].toString().indexOf('dev');
        var uat_pos = this.outS12[i][Domain].toString().indexOf('uat');
        var qa_pos = this.outS12[i][Domain].toString().indexOf('qa');
        var test_pos = this.outS12[i][Domain].toString().indexOf('test');
        var stag_pos = this.outS12[i][Domain].toString().indexOf('stag');
        var temp_pos = this.outS12[i][Domain].toString().indexOf('temp');
        var tmp_pos = this.outS12[i][Domain].toString().indexOf('tmp');
        if (dev_pos>-1){
          c=c++
        }else if(uat_pos>-1){
          d=d++
        }else if(qa_pos>-1){
          e=e++
        }else if(test_pos>-1){
          f=f++
        }else if(stag_pos>-1){
          g=g++
        }else if(temp_pos>-1){
          h=h++
        }else if(tmp_pos>-1){
          j=j++
        };
        this.outS12["data"]=[[['dev','uat','qa','test','stag','temp','tmp'],[c,d,e,f,g,h,j]]];
        console.log(c)
     };*/
    },
  },
  computed: {
    formIsValid () {
      return (
        this.form.entityName &&
        this.form.searchDomain &&
        this.form.keyword
      )
    },
  },
};
/*function init() {
  var c=0;
  var d=0;
  var e=0;
  var f=0;
  var g=0;
  var h=0;
  var j=0;
  return { c, d, e, f, g, h, j };
}*/
</script>
<style lang='scss'>
.scroll{
  width:3000px;
  max-height:500px;
  overflow: scroll;
  margin-bottom: 20px;
}
table {
  font-family: 'Open Sans', sans-serif;
  width: 750px;
  border-collapse: scroll;
  border: 3px solid #44475C;
  overflow: scroll;
  margin: 10px 10px 0 10px;
}

table th {
  text-transform: uppercase;
  text-align: left;
  background: #44475C;
  color: #FFF;
  padding: 8px;
  min-width: 30px;
}

table td {
  text-align: left;
  padding: 8px;
  border-right: 2px solid #7D82A8;
}
table td:last-child {
  border-right: none;
}
table tbody tr:nth-child(2n) td {
  background: #D4D8F9;
}
</style>
<!--<template>
  <div>
    <!--input section
    <v-form class="col-12" ref="form" @submit.prevent="getOutput">
      <br>
      <v-text-field
        label="Entity Name"
        v-model="form.entityName"
        :rules="inputRules"
        :disabled="gettingData"
        solo
      ></v-text-field>

      <v-text-field
        label="Search domain"
        v-model="form.searchDomain"
        :rules="inputRules"
        :disabled="gettingData"
        solo
      ></v-text-field>

      <v-text-field
        label="Keyword"
        v-model="form.keyword"
        :rules="inputRules"
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
    <v-card>
      <div>
        <!--Subdomains containing malicious URLs
        <v-card-title> Domains containing malicious URLs</v-card-title>
        <v-card-text>
          <div class="scroll">
            <table id="outS16" class='text_left'>
            <thead>
              <tr>
                <th v-for="(key_, index) in Object.keys(this.outS16[0])" :key="index">{{key_}}</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="(row, index) in this.outS16" :key="index">
                <td v-for="(key_, index) in Object.keys(this.outS16[0])" :key="index">{{row[key_]}}</td>
              </tr>
            </tbody>
            </table>
          </div>
        </v-card-text>
      </div>
    </v-card>
    <v-card>
      <div class='domain_types'>
        <v-card-title>Distribution of domains by type</v-card-title>
        <v-card-text>
           <div class="row">
              <div class="col">
                  <GChart
                    type="PieChart"
                    :data="outS12.data"
                    :options="outS12.options"
                  />
              </div>
           </div>
        </v-card-text>
      </div>
    </v-card>
    <v-card>
      <div>
        <!--Subdomains containing login portals
        <v-card-title> Subdomains containing login portals</v-card-title>
        <v-card-text>
          <div class="scroll">
            <table id="outS15" class='text_left'>
            <thead>
              <tr>
                <th v-for="(key_, index) in Object.keys(this.outS15[0])" :key="index">{{key_}}</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="(row, index) in this.outS15" :key="index">
                <td v-for="(key_, index) in Object.keys(this.outS15[0])" :key="index">{{row[key_]}}</td>
              </tr>
            </tbody>
            </table>
          </div>
        </v-card-text>
      </div>
    </v-card>
  </div>
</template>
<script>
import getOutput from '@/services/getOutput'
export default {
  data() { 
     const defaultForm = Object.freeze({
      entityName: "",
      searchDomain: "",
      keyword: "",
    })
    const defaultTable = [
        {"col 1": '-', "col 2":'-', "col 3":'-', "col 4":'-'}
    ]
    return {
      form: Object.assign({}, defaultForm),
      inputRules: [
        value => !!value || 'This field is required',
      ],
      defaultForm,
      gettingData: false,
      panelDisabled: true,
      outS12: defaultTable,
      outS15: {"col 1": '-', "col 2":'-', "col 3":'-'},
      outS16: [{"col 1": '-', "col 2":'-', "col 3":'-', 
              "col 4":'-', 'col 5':'-', 'col 6':'-'}
      ],
      mongoDB: {'password': 'jonathan', 'database': 'ClientData'
      },
    };
  },
  methods:{
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
    async getOutput(){
      this.gettingData = true;
      this.panelDisabled = true;
      const response = await getOutput.getOutput({
        entityName: this.entityName,
        searchDomain: this.searchDomain,
        keyword: this.keyword
      });
      this.outS12 = response.data['outS12'];
      this.cleanOutS12()
      this.outS15 = response.data['outS15'];
      this.cleanOutS15()
      this.outS16 = response.data['outS16'];
      this.loadingStatus = "Done!"
    },
    cleanOutS12(){
      var a=0
      var b=0
      var c=0
      var d=0
      var e=0
      var f=0
      var g=0
      for (i=0; i<this.outS12.length; i++){
        if('dev' in outS12[i].Domain){
          a=a++
        }else if('uat' in outS12[i].Domain){
          b=b++
        }else if('qa' in outS12[i].Domain){
          c=c++
        }else if('test' in outS12[i].Domain){
          d=d++
        }else if('stag' in outS12[i].Domain){
          e=e++
        }else if('temp' in outS12[i].Domain){
          f=f++
        }else{
          g=g++
        }
      };
      console.log(a)
      this.outS12['data']=[['Types of non-prod entry points','No, of domains']]
    },
    cleanOutS15(){
      this.outS15=this.outS15.map((e)=>{
        return{
          hostname:e.hostname,
          domain:e.Domain,
          LoginPortal:e.LoginPortal
        }
      })
    }
  },
  computed: {
    formIsValid () {
      return (
        this.form.entityName &&
        this.form.searchDomain &&
        this.form.keyword
      )
    }
  }
};
</script>-->