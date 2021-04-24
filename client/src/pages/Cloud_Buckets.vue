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
        <v-card>
            <div class="cloud_buckets">
            <v-card-title>Buckets containing " {{form.keyword}} "</v-card-title>
            <v-card-subtitle>Source(s): <strong>grayhatwarfare</strong></v-card-subtitle>
            <!--Bucket names containing keyword-->
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
                    </div>
                </div>
            </div>
        </v-card>
        <br>
        <!--No. of files containing keyword by buckets-->
        <v-card>
            <v-card-title>Sensitive files containing " {{form.keyword}} "</v-card-title>
            <v-card-subtitle>List of counts of sensitive files containing  <strong>" {{form.keyword}} "</strong> by bucket<br>
                             Source(s): <strong>grayhatwarfare</strong></v-card-subtitle>
            <div class="scroll">
                <v-simple-table fixed-header height="300px">
                    <template v-slot:default id="outS32" class='text_left'>
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
                    </template>
                </v-simple-table>
            </div>
        </v-card>
        <br>
        <!--Dubious files-->
        <v-card>
            <v-card-title>Dubious files</v-card-title>
            <v-card-subtitle>Source(s): <strong>grayhatwarfare, node-fetch</strong></v-card-subtitle>
            <v-card-text>{{this.outS33_dubiousFile.length-1}} file(s) found.</v-card-text>
            <div class="scroll">
                <v-simple-table fixed-header height="300px">
                    <template v-slot:default id="outS33_dubiousFile" class='text_left'>
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
                    </template>
                </v-simple-table>
            </div>
        </v-card>
        <br>
        <!--Files that cannot be connected-->
        <v-card>
            <v-card-title>Unconnectable files</v-card-title>
           <v-card-subtitle>Source(s): <strong>grayhatwarfare, node-fetch</strong></v-card-subtitle>
            <v-card-text>{{this.outS33_failConnected.length-1}} file(s) found.</v-card-text>
            <div class="scroll">
                <v-simple-table fixed-header height="300px">
                    <template v-slot:default id="outS33_failConnected" class='text_left'>
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
                    </template>
                </v-simple-table>
            </div>
        </v-card>
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
        {"-": '-', "-":'-', "-":'-'}
    ]

    return {
      form: Object.assign({}, defaultForm),
      entityNameInputRules: [
        value => !!value || 'This field is required',
        value => this.checkEntityNameValidity() || 'Entity name should not contain /\\\. "$*<>:|?'
      ],
      searchDomainInputRules: [
        value => !!value || 'This field is required',
        value => this.checkSearchDomainValidity() || 'Please skip https://www. or http://www. in your domain name',
        value => value.includes(".") || 'This is not a valid domain name'
      ],
      keywordInputRules: [
        value => !!value || 'This field is required',
      ],
      defaultForm,
      gettingData: false,
      panelDisabled: true,
      outS31: [
        {"-": '-', "-":'-', "-":'-'}
    ],
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
    cleanOutS31(){
      this.outS31 = this.outS31.map((e) => {
        return {
          Bucket: e.Bucket,
          FileCount: e.FileCount,
          BucketType: e.Type,
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
      for (var [key, value] of sumByType) {  //or sumByType.entries()
        this.outS31_fileCount_byType["data"].push([key,value]);
      };
    },
    cleanOutS32() {
      this.outS32 = this.outS32.map((e) => {
        return {
          Bucket: e.Bucket,
          "File count": e.BucketCount
        }
      });
    },
    cleanOutS33_dubiousFile() {
      this.outS33_dubiousFile = this.outS33_dubiousFile.map((e) => {
        return {
          "File name": e.Filename,
          URL: e.Url,
          "Bucket type": e.Type
        }
      });
    },
    cleanOutS33_failConnected() {
      this.outS33_failConnected = this.outS33_failConnected.map((e) => {
        return {
          "File name": e.Filename,
          URL: e.Url,
          "Bucket type": e.Type
        }
      });
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
};
</script>

<style>
.v-card__title {
  color: rgb(62, 169, 120)!important;
}
</style>