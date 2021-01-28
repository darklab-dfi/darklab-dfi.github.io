<template>
  <div>
    <!--input section -->
    <v-card class="inputSection">
      <v-form class="col-12" ref="form" @submit.prevent="getOutput">
        <br>
        <v-text-field
          label="Entity Name"
          v-model="form.entityName"
          :rules="inputRules"
          :disabled="gettingData"
        ></v-text-field>

        <v-text-field
          label="Search domain"
          v-model="form.searchDomain"
          :rules="inputRules"
          :disabled="gettingData"
        ></v-text-field>

        <v-text-field
          label="Keyword"
          v-model="form.keyword"
          :rules="inputRules"
          :disabled="gettingData"
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
    </v-card>

    <br>
    <br>

    <!--change panel color in header/content tag (background;word): style="background:#23B5C3;color:white"-->
    <!--email address-->
    <v-card>
      <div class="email_address">
        <v-card-title><h6>Email address</h6></v-card-title>
        <v-expansion-panels focusable :disabled="panelDisabled">
          <!--SPF record-->
          <v-expansion-panel>
            <v-expansion-panel-header>SPF record</v-expansion-panel-header>
            <v-expansion-panel-content>
              <div class="scroll">
                <table id="outS17" class='text_left'>
                <thead>
                  <tr>
                    <th v-for="(key_, index) in Object.keys(outS17[0])" :key="index">{{key_}}</th>
                  </tr>
                </thead>
                <tbody>
                  <tr v-for="(row, index) in outS17" :key="index">
                    <td v-for="(key_, index) in Object.keys(outS17[0])" :key="index">{{row[key_]}}</td>
                  </tr>
                </tbody>
                </table>
              </div>
            </v-expansion-panel-content>
          </v-expansion-panel>

          <!--DMARC record-->
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
          </v-expansion-panel>

          <!--Emails related to the client’s domain-->
          <v-expansion-panel>
            <v-expansion-panel-header>Emails related to target domain</v-expansion-panel-header>
            <v-expansion-panel-content>
              <div class="scroll">
                <table id="outS20" class='text_left'>
                <thead>
                  <tr>
                    <th v-for="(key_, index) in Object.keys(outS20[0])" :key="index">{{key_}}</th>
                  </tr>
                </thead>
                <tbody>
                  <tr v-for="(row, index) in outS20" :key="index">
                    <td v-for="(key_, index) in Object.keys(outS20[0])" :key="index">{{row[key_]}}</td>
                  </tr>
                </tbody>
                </table>
              </div>
            </v-expansion-panel-content>
          </v-expansion-panel>
        </v-expansion-panels>
      </div>
    </v-card>

    <br>

<!--Domains with similar names-->
    <v-card>
      <div class="domain_similar_name">
        <v-card-title><h6>Domains with similar names</h6></v-card-title>
        <v-expansion-panels focusable :disabled="panelDisabled">
          <!--Domain List-->
          <v-expansion-panel>
            <v-expansion-panel-header>Domain List</v-expansion-panel-header>
            <v-expansion-panel-content>
              <br>
              <h5>There are <strong>{{countSimilarDomain}}</strong> domains names similar to {{form.searchDomain}} </h5>
              <div class="scroll">
                <table id="outS19" class='text_left'>
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
                </table>
              </div>
            </v-expansion-panel-content>
          </v-expansion-panel>
        </v-expansion-panels>
      </div>
    </v-card>

    <br>

    <!--Cloud buckets-->
    <v-card>
      <div class="cloud_buckets">
        <v-card-title><h6>Cloud buckets</h6></v-card-title>
        <v-expansion-panels focusable :disabled="panelDisabled">
          <!--Buckets names containing keyword-->
          <v-expansion-panel>
            <v-expansion-panel-header>Buckets with names containing keyword {{form.keyword}}</v-expansion-panel-header>
            <v-expansion-panel-content>
              <div class="row">
                <div class="col">
                  <GChart
                    type="PieChart"
                    :data="outS31_top3_bucket.data"
                    :options="outS31_top3_bucket.options"
                  />
                </div>
                <div class="col">
                  <GChart
                    type="ColumnChart"
                    :data="outS31_fileCount_byType.data"
                    :options="outS31_fileCount_byType.options"
                  />
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
              </div>
            </v-expansion-panel-content>
          </v-expansion-panel>

          <!--Files containing keyword in buckets-->
          <v-expansion-panel>
            <v-expansion-panel-header>Sensitive files containing keyword {{form.keyword}}</v-expansion-panel-header>
            <v-expansion-panel-content>
              <div class="scroll">
                <table id="outS32" class='text_left'>
                <thead>
                  <tr>
                    <th v-for="(key_, index) in Object.keys(outS32[0])" :key="index">{{key_}}</th>
                  </tr>
                </thead>
                <tbody>
                  <tr v-for="(row, index) in outS32" :key="index">
                    <td v-for="(key_, index) in Object.keys(outS32[0])" :key="index">{{row[key_]}}</td>
                  </tr>
                </tbody>
                </table>
              </div>
            </v-expansion-panel-content>
          </v-expansion-panel>

          <!--Dubious files-->
          <v-expansion-panel>
            <v-expansion-panel-header>Dubious files</v-expansion-panel-header>
            <v-expansion-panel-content>
              <div class="scroll">
                <table id="outS33_dubiousFile" class='text_left'>
                <thead>
                  <tr>
                    <th v-for="(key_, index) in Object.keys(outS33_dubiousFile[0])" :key="index">{{key_}}</th>
                  </tr>
                </thead>
                <tbody>
                  <tr v-for="(row, index) in outS33_dubiousFile" :key="index">
                    <td v-for="(key_, index) in Object.keys(outS33_dubiousFile[0])" :key="index">{{row[key_]}}</td>
                  </tr>
                </tbody>
                </table>
              </div>
            </v-expansion-panel-content>
          </v-expansion-panel>

          <!--Files that cannot be conneted-->
          <v-expansion-panel>
            <v-expansion-panel-header>Unconnectable files</v-expansion-panel-header>
            <v-expansion-panel-content>
              <div class="scroll">
                <table id="outS33_failConnected" class='text_left'>
                <thead>
                  <tr>
                    <th v-for="(key_, index) in Object.keys(outS33_failConnected[0])" :key="index">{{key_}}</th>
                  </tr>
                </thead>
                <tbody>
                  <tr v-for="(row, index) in outS33_failConnected" :key="index">
                    <td v-for="(key_, index) in Object.keys(outS33_failConnected[0])" :key="index">{{row[key_]}}</td>
                  </tr>
                </tbody>
                </table>
              </div>
            </v-expansion-panel-content>
          </v-expansion-panel>
        </v-expansion-panels>
        </div>
    </v-card>
    <br>
  </div>
</template>

<script>
import getOutput from "@/services/getOutput";
import * as d3 from "d3";

export default {
  data() {
    const defaultForm = Object.freeze({
      entityName: "",
      searchDomain: "",
      keyword: "",
    })

    const defaultTable = [
        {"col 1": '[row 1 col 1]', "col 2":'[row 1 col 2]', "col 3":'[row 1 col 3]', "col 4":'[row 1 col 4]'}
    ]

    return {
      form: Object.assign({}, defaultForm),
      inputRules: [
        value => !!value || 'This field is required',
      ],
      defaultForm,
      gettingData: false,
      panelDisabled: true,
      outS11: defaultTable,
      outS12: defaultTable,
      outS13: defaultTable,
      outS14: defaultTable,
      outS15: defaultTable,
      outS16: defaultTable,
      outS17: defaultTable,
      outS18: "DMARC record data...",
      outS19: defaultTable,
      outS110: defaultTable,
      outS20: defaultTable,
      outS31: defaultTable,
      outS32: defaultTable,
      outS33_dubiousFile: defaultTable,
      outS33_failConnected: defaultTable,
      outS31_top3_bucket:{
        data: [
          ["Buckets","Number of files"]
        ],
        options: {title:"Top 3 buckets with largest file count",theme: 'material',height:350}
      },      
      outS31_fileCount_byType:{
        data: [
          ["Types","Number of files"]
        ],
        //options: {chart:{title:"File Count by Bucket Type"},legend: { position: "none" }} <---material chart
        options: {title:"File count by bucket type",legend: { position: "none" },theme: 'material',height:350}
      },
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
      this.outS17 = response.data["outS17"];
      this.cleanOutS17()
      this.outS18 = response.data["outS18"];
      this.cleanOutS18()
      this.outS19 = response.data["outS19"];
      this.cleanOutS19()
      this.outS20 = response.data["outS20"];
      this.cleanOutS20()
      this.outS31 = response.data["outS31"];
      this.cleanOutS31()
      this.outS32 = response.data["outS32"];
      this.cleanOutS32()
      this.outS33_dubiousFile = response.data["outS33_dubiousFile"];
      this.cleanOutS33_dubiousFile()
      this.outS33_failConnected = response.data["outS33_failConnected"];
      this.cleanOutS33_failConnected()
      this.panelDisabled = false;
      this.gettingData = false;
      this.notifyFinish()
    },
    cleanOutS17() {
      this.outS17 = this.outS17.map((e) => {
        return {
          "IP Address": e.SPFOn,
          "Record Type": e.RecordType,
          Validation: e.Validation
        }
      });
    },
    cleanOutS18(){
      //organize and add decription in DMARC record
      const dmarc = require('dmarc-parse');
      this.outS18 = Object.values(dmarc(this.outS18)["tags"])
    },
    cleanOutS19() {
      //cleaning data
      this.outS19 = this.outS19.map((e) => {
        return {
          "Domain Name": e.Domain,
          "Server IP address": e.ServerIP,
        }
      });

      //count similar domains
      this.countSimilarDomain=this.outS19.length;
    },
    cleanOutS20() {
      this.outS20 = this.outS20.map((e) => {
        return {
          Email: e.Value,
          Position: e.Position,
          Department: e.Department
        }
      });
    },
    cleanOutS31(){
      //cleaning data
      this.outS31 = this.outS31.map((e) => {
        return {
          Bucket: e.Bucket,
          FileCount: e.FileCount,
          BucketType: e.Type,
          //"List of sensitive files": e.PotentialFileLists,
          //"Sensitive file count": e.MatchedKeywordFilesCount
        }
      });
    
      //top 3 buckets pie chart
      this.outS31_top3_bucket["data"] = [["Buckets","Number of files"]];
      var sortedFileCount = this.outS31.slice().sort((a, b) => d3.descending(a.FileCount, b.FileCount));
      if (Array.isArray(sortedFileCount) && sortedFileCount.length > 3) {
        for (var i = 0; i < 3; i++) {
          this.outS31_top3_bucket["data"].push([sortedFileCount[i]["Bucket"],sortedFileCount[i]["FileCount"]]);
        };
        sortedFileCount.shift();
        sortedFileCount.shift();
        sortedFileCount.shift();
        var fileCount_others = d3.sum(sortedFileCount, d => d.FileCount);
        this.outS31_top3_bucket["data"].push(["Others",fileCount_others]);
      } else {
        while (Array.isArray(sortedFileCount) && sortedFileCount.length > 0) {
          this.outS31_top3_bucket["data"].push([sortedFileCount[0]["Bucket"],sortedFileCount[0]["FileCount"]]);
          sortedFileCount.shift();
        };
      };

      //file count by bucket type bar chart
      this.outS31_fileCount_byType["data"] = [["Types","Number of files"]];
      var sumByType = d3.rollup(this.outS31, v => d3.sum(v, d => d.FileCount), d => d.BucketType);
      //this.outS31_fileCount_byType['data']['labels'] = Array.from(sumByType.keys());    //for chartist (to be deleted)
      //this.outS31_fileCount_byType['data']['series'][0] = Array.from(sumByType.values());
      for (var [key, value] of sumByType) {  //or sumByType.entries()
        this.outS31_fileCount_byType["data"].push([key,value]);
      };
    },
    cleanOutS32() {
      this.outS32 = this.outS32.map((e) => {
        return {
          Bucket: e.Bucket,
          "Files count": e.BucketCount
        }
      });
    },
    cleanOutS33_dubiousFile() {
      this.outS33_dubiousFile = this.outS33_dubiousFile.map((e) => {
        return {
          "File name": e.Filename,
          Url: e.Url,
          "Bucket type": e.Type
        }
      });
    },
    cleanOutS33_failConnected() {
      this.outS33_failConnected = this.outS33_failConnected.map((e) => {
        return {
          "File name": e.Filename,
          Url: e.Url,
          "Bucket type": e.Type
        }
      });
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
</script>

<style>

</style>