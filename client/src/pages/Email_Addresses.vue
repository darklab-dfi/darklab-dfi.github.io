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
    <!--change panel color in header/content tag (background;word): style="background:#23B5C3;color:white"-->
    <!--SPF records-->
    <v-card>
      <div class="email_address">
        <v-card-title>SPF records</v-card-title>
        <v-card-subtitle>List of all SPF records corresponding to email addresses of <strong>{{form.searchDomain}}</strong><br>
                         Source(s): <strong>dns</strong></v-card-subtitle>
        <v-card-text><strong>{{this.outS17.length-1}}</strong> record(s) found.</v-card-text> 
        <div class="scroll">
          <v-simple-table fixed-header height="300px">
            <template v-slot:default id="outS17" class='text_left'>
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
            </template>
          </v-simple-table>
        </div>
      </div>
    </v-card>
    <br>
    <!--DMARC records-->
    <v-card>
      <div class="dmarc_record">
        <v-card-title> DMARC records</v-card-title>
        <v-card-subtitle>List of all DMARC records corresponding to email addresses of <strong>{{form.searchDomain}}</strong><br>
                          Source(s): <strong>dmarc-solution</strong></v-card-subtitle>
        <div class="scroll">
          <v-simple-table fixed-header height="300px">
            <template v-slot:default id="outS18" class='text_left'>
              <thead>
                <tr>
                  <th v-for="(key_, index) in Object.keys(outS18[0])" :key="index">{{key_}}</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="(row, index) in outS18" :key="index">
                <td v-for="(key_, index) in Object.keys(outS18[0])" :key="index">{{row[key_]}}</td>
              </tr>
              </tbody>
            </template>
          </v-simple-table>
        </div>
      </div>
    </v-card>
    <br>
    <!--Email addresses related to client’s domain-->
    <v-card>
      <v-card-title>Email addresses related to {{form.searchDomain}}</v-card-title>
      <v-card-subtitle>Source(s): <strong>hunter.io</strong></v-card-subtitle>
      <v-card-text><strong>{{this.outS20.length-1}}</strong> record(s) found.</v-card-text> 
      <div class="scroll">
        <v-simple-table fixed-header height="300px">
          <template v-slot:default id="outS20" class='text_left'>
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
          </template>
        </v-simple-table>
      </div>
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
      outS17: defaultTable,
      outS18: "-",
      outS20: defaultTable,
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
      this.outS20 = response.data["outS20"];
      this.cleanOutS20()
      this.outS31 = response.data["outS31"];
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
    cleanOutS20() {
      this.outS20 = this.outS20.map((e) => {
        return {
          Email: e.Value,
          Position: e.Position,
          Department: e.Department
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