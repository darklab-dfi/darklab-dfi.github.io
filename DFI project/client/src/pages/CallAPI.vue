<template>
    <div class="row">
      <div class="col-12">
        <card :title="table1.title" :subTitle="table1.subTitle">
          <div slot="raw-content" class="table-responsive">
            <paper-table :data="table1.data" :columns="table1.columns">

            </paper-table>
          </div>
        </card>
      </div>

      <div class="col-12">
        <card class="card-plain">
          <div class="table-full-width table-responsive">
            <paper-table type="hover" :title="table2.title" :sub-title="table2.subTitle" :data="table2.data"
                         :columns="table2.columns">

            </paper-table>
          </div>
        </card>
      </div>
      <div class="text-center">
        <input 
          type="email" 
          name="email" 
          v-model="email"
          placeholder="email"/>
        <br>
        <br>
        <input 
          type="password" 
          name="password" 
          v-model="password"
          placeholder="password"/>
        <br>
        <br>
        <button
          type="info"
          round
          @click="register">
          Register
        </button>
      </div>
    </div>
</template>
<script>
import AuthenticationService from '@/services/AuthenticationService'
import { PaperTable } from "@/components";
const tableColumns = ["Id", "Name", "Salary", "Country", "City"];
const tableData = [
  {
    id: 1,
    name: "Dakota Rice",
    salary: "$36.738",
    country: "Niger",
    city: "Oud-Turnhout"
  },
  {
    id: 2,
    name: "Minerva Hooper",
    salary: "$23,789",
    country: "Curaçao",
    city: "Sinaai-Waas"
  },
  {
    id: 3,
    name: "Sage Rodriguez",
    salary: "$56,142",
    country: "Netherlands",
    city: "Baileux"
  },
  {
    id: 4,
    name: "Philip Chaney",
    salary: "$38,735",
    country: "Korea, South",
    city: "Overland Park"
  },
  {
    id: 5,
    name: "Doris Greene",
    salary: "$63,542",
    country: "Malawi",
    city: "Feldkirchen in Kärnten"
  }
];

export default {
  components: {
    PaperTable
  },
  data() {
    return {
      table1: {
        title: "Stripped Table",
        subTitle: "Here is a subtitle for this table",
        columns: [...tableColumns],
        data: [...tableData]
      },
      table2: {
        title: "Table on Plain Background",
        subTitle: "Here is a subtitle for this table",
        columns: [...tableColumns],
        data: [...tableData]
      },
      email: '',
      password: ''
    };
  },
  methods:{
    async register(){
      const response = await AuthenticationService.register({
        email: this.email,
        password: this.password
      })
      console.log(response.data)
    },
    async securityTrailFunc() {
      var prefixURL = 'https://cors-anywhere.herokuapp.com/'
      var searchDomains = "pwc.com";
      var url =prefixURL + 'https://api.securitytrails.com/v1/history/' + searchDomains + '/dns/a';
      var headers = {
        "accept": "application/json",
        "apikey": "DQBlP4wW3HFKjAA12KHc6NtiYATfTVZP",
      };
      const request_securityTrail = await fetch(url, { method: 'GET', headers: headers});
      const data = await request_securityTrail.json();
      alert(JSON.stringify(data));
    },
    async hunterioFunc(){
      var prefixURL = 'https://cors-anywhere.herokuapp.com/'
      var searchDomains = "pwc.com";
      var hunterAPIkey ="22850ea6e4f33099e48217886b978b65c82db488";
      var url = prefixURL + 'https://api.hunter.io/v2/domain-search?domain=' + searchDomains + '&api_key=' + hunterAPIkey + '&limit=10';
      var headers = {
        "accept": "application/json",
        "apikey": hunterAPIkey
      };
      const request_hunterio = await fetch(url, { method: 'GET', headers: headers}); //must include await
      const data = await request_hunterio.json(); //must include await so that will wait for data return
      alert(JSON.stringify(data));
    }
  }
};
</script>
<style>
</style>
